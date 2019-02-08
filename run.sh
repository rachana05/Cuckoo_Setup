#!/bin/bash
while (pgrep VirtualBox >1);do
	sleep 1
done &&	python report.py
