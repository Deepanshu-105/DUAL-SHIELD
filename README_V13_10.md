# v13.10 - Windows: writer identified by the KERNEL (ETW), no driver
multi/win_etw.py listens to the kernel provider Microsoft-Windows-Kernel-File (every create/write/rename/delete with the process id), keeps the last 5 s per process and
answers writers_under(folder). shield_os.pids_with_open_file_under() on Windows asks it first and falls back to the slow scan if ETW is off.
The guard starts it automatically on Windows (prints ETW_ON or ETW_OFF).  Needs: Administrator + pip install pywintrace.
Logic tested on Linux with simulated events (multi/test_win_etw.py, 4 checks). The REAL ETW path is NOT tested yet - run on Windows (Administrator PowerShell):
    pip install pywintrace
    python multi\win_etw_probe.py          -> PROBE_OK writer pid N known after X s   (or send the output if PROBE_FAIL)
Then re-run  python ransomware\results_table.py --live  to see the new kill time.
Not a minifilter driver: ETW is notified after the operation, so it cannot BLOCK a write, only name the writer fast; a driver is still the only way to block it.
