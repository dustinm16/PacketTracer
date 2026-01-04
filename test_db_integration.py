#!/usr/bin/env python3
"""Quick test to verify database writes during packet capture.

Run with: sudo .venv/bin/python test_db_integration.py

This test:
1. Creates a Dashboard with database integration
2. Captures traffic for a few seconds
3. Verifies data was written to the SQLite database
"""
import os
import sys
import time
import sqlite3
import subprocess
import argparse

def main():
    parser = argparse.ArgumentParser(description='Test database integration')
    parser.add_argument('-i', '--interface', default='lo', help='Network interface to capture on')
    parser.add_argument('-t', '--time', type=int, default=3, help='Capture time in seconds')
    parser.add_argument('--keep-db', action='store_true', help='Keep database after test')
    args = parser.parse_args()

    # Database path
    db_path = os.path.expanduser("~/.packettracer/data.db")

    # Clean up test database unless keeping
    if os.path.exists(db_path) and not args.keep_db:
        os.remove(db_path)
        print(f"Removed existing database")

    from dashboard.app import Dashboard

    print(f"Creating dashboard (interface={args.interface})...")
    d = Dashboard(interface=args.interface, bpf_filter='ip')
    print(f"Session ID: {d.session_id}")
    print(f"Database writer started: {d.db_writer._thread.is_alive()}")

    # Start capturing
    print("\nStarting capture...")
    d.sniffer.callback = d._packet_callback
    d.sniffer.start()
    d.geo_resolver.start_background_resolver()
    d.dns_resolver.start()

    # Generate some traffic by pinging localhost (if using lo interface)
    if args.interface == 'lo':
        print("Generating traffic (ping localhost)...")
        subprocess.Popen(['ping', '-c', '5', '127.0.0.1'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Let it run
    print(f"Capturing for {args.time} seconds...")
    time.sleep(args.time)

    # Check writer stats before stop
    writer_stats = d.db_writer.stats
    print(f"\nWriter stats: queued={writer_stats['queued']}, completed={writer_stats['completed']}, pending={writer_stats['pending']}")

    # Stop
    print("Stopping capture...")
    d.stop()

    # Final stats
    print(f"Final packet count: {d._packet_count}")

    # Check database
    print("\n" + "="*60)
    print("DATABASE VERIFICATION")
    print("="*60)

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    # Check sessions
    cursor = conn.execute("SELECT * FROM sessions")
    sessions = cursor.fetchall()
    print(f"\nSessions: {len(sessions)}")
    for s in sessions:
        duration = (s['ended_at'] or time.time()) - s['started_at']
        print(f"  ID={s['id']}, interface={s['interface']}")
        print(f"    Duration: {duration:.1f}s, Packets: {s['total_packets']}, Bytes: {s['total_bytes']}")

    # Check flows
    cursor = conn.execute("SELECT COUNT(*) as c FROM flows")
    flow_count = cursor.fetchone()['c']
    print(f"\nFlows: {flow_count}")

    if flow_count > 0:
        cursor = conn.execute("""
            SELECT flow_key, src_ip, dst_ip, protocol_name,
                   packets_sent, packets_recv, bytes_sent, bytes_recv,
                   dst_hostname, dst_domain, dst_country, dst_city
            FROM flows
            ORDER BY bytes_sent + bytes_recv DESC
            LIMIT 10
        """)
        for f in cursor.fetchall():
            total_pkts = f['packets_sent'] + f['packets_recv']
            total_bytes = f['bytes_sent'] + f['bytes_recv']
            host = f['dst_hostname'] or f['dst_domain'] or ''
            geo = f['dst_country'] or ''
            print(f"  {f['src_ip']} -> {f['dst_ip']} ({f['protocol_name']})")
            print(f"    {total_pkts} pkts, {total_bytes} bytes")
            if host:
                print(f"    Host: {host}")
            if geo:
                print(f"    Location: {f['dst_city']}, {geo}" if f['dst_city'] else f"    Location: {geo}")

    # Check port stats
    cursor = conn.execute("SELECT COUNT(*) as c FROM port_stats")
    port_count = cursor.fetchone()['c']
    print(f"\nPort stats entries: {port_count}")

    if port_count > 0:
        cursor = conn.execute("""
            SELECT port, protocol, packets_in, packets_out, bytes_in, bytes_out
            FROM port_stats
            ORDER BY bytes_in + bytes_out DESC
            LIMIT 5
        """)
        for p in cursor.fetchall():
            total_pkts = p['packets_in'] + p['packets_out']
            total_bytes = p['bytes_in'] + p['bytes_out']
            print(f"  Port {p['port']}/{p['protocol']}: {total_pkts} pkts, {total_bytes} bytes")

    # Check caches
    cursor = conn.execute("SELECT COUNT(*) as c FROM geo_cache")
    geo_count = cursor.fetchone()['c']
    cursor = conn.execute("SELECT COUNT(*) as c FROM dns_cache")
    dns_count = cursor.fetchone()['c']
    print(f"\nCache entries: {geo_count} geo, {dns_count} DNS")

    # Check tables
    cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
    tables = [r['name'] for r in cursor.fetchall()]
    print(f"\nDatabase tables: {len(tables)}")
    for t in tables:
        cursor = conn.execute(f"SELECT COUNT(*) as c FROM {t}")
        count = cursor.fetchone()['c']
        if count > 0:
            print(f"  {t}: {count} rows")

    conn.close()

    print("\n" + "="*60)
    print("TEST COMPLETE")
    print("="*60)

    # Summary
    success = sessions and d._packet_count > 0
    if success:
        print("\n[SUCCESS] Database integration is working!")
        print(f"  - Captured {d._packet_count} packets")
        print(f"  - Recorded {flow_count} flows")
        print(f"  - Database: {db_path} ({os.path.getsize(db_path)} bytes)")
    else:
        print("\n[WARNING] No data captured")
        print("  Try with a different interface: sudo .venv/bin/python test_db_integration.py -i eth0")

if __name__ == '__main__':
    main()
