# home_assignment_01.2023

# Cyber Scans System

The Cyber Scans System is designed to scan a list of URLs with potential security threats. 
The scan verdict and scan status will be stored on external systems (such as DataBase and Cache). 

# system flow

Ingestion system:

1. The Cyber Scan System receive multiple requests.
2. Requests are recorded in DB and Cache.
3. Requests are pushed to Queue.
4. The client receieve a unique scan_id.

Process system:

5. Requests are dequeued from Queue.
6. The requests proccessed cosecutive in bulks.
7. The scans are handled by the scan handler.
8. Requests updated in DB and Cache.

Scan Status:

9. Requests recevied with scan_id.
10. Each request is checked againgt Cache.
11. If no match is found, The system will try to check againgt DB.
12. If no match is found, The system will notify that the scan was not found.

# Features

1. Fast scanning speed
2. Ability to handle multiple requests in parallel
3. Ability to get scan information (status/verdict etc)
4. Integrated with external tools

# Getting Started

1. clone home_assignment_01.2023 into your computer or server.
2. make sure all dependencies are installed (requierments.txt file is attached to this repository).
3. run dispatching_system.py file.
4. run client.py file for new requests.
5. run get_status.py file for scan status.

# Usage

The Cyber Scan System can be used to scan a variety of lists of URLs.

# Fututre Work

1. Adding get_scan_verdict endpoint.
2. Complete tests coverage.
3. Improve scan handler to me more effective.
4. Support additional scans types.
