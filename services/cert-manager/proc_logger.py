"""
Process logger for supervisord processes.
Reads log streams from multiple processes and outputs them to stdout with prefixes.
"""

import os
import sys
import time
import threading
from typing import Dict, TextIO


MAX_LOG_CHUNK_CHARS = 65536
MAX_LOG_CHUNKS_PER_PASS = 1024


class ProcessLogger:
    def __init__(self, log_files: Dict[str, str]):
        """
        Initialize the process logger.

        Args:
            log_files: Dictionary mapping process names to their log file paths
        """
        self.log_files = log_files
        self.file_handles: Dict[str, TextIO] = {}
        self.running = True

    def _open_log_files(self):
        """Open log files"""
        for process_name, log_path in self.log_files.items():
            try:
                # Wait for log file to exist
                while not os.path.exists(log_path) and self.running:
                    time.sleep(1)

                file_handle = open(log_path, "r", encoding="utf-8", errors="ignore")
                self.file_handles[process_name] = file_handle
                print(f"[proc_logger] Started monitoring {process_name} -> {log_path}", flush=True)

            except Exception as e:
                print(f"[proc_logger] Error opening {log_path}: {e}", flush=True)

    def _tail_file(self, process_name: str):
        """Tail a specific log file and output with prefix."""
        if process_name not in self.file_handles:
            return

        while self.running:
            try:
                file_handle = self.file_handles[process_name]
                if os.fstat(file_handle.fileno()).st_size < file_handle.tell():
                    file_handle.seek(0)
                for _ in range(MAX_LOG_CHUNKS_PER_PASS):
                    line = file_handle.readline(MAX_LOG_CHUNK_CHARS)
                    if not line:
                        self._reopen_rotated_log(process_name)
                        break
                    # Split oversized records instead of retaining an entire line.
                    print(
                        f"[{process_name}] {line}",
                        end="" if line.endswith("\n") else "\n",
                        flush=True,
                    )

            except Exception as e:
                print(f"[proc_logger] Error reading {process_name}: {e}", flush=True)

            finally:
                time.sleep(1)

    def _reopen_rotated_log(self, process_name: str):
        """Follow the current log after draining the previous file."""
        file_handle = self.file_handles[process_name]
        try:
            current_stat = os.stat(self.log_files[process_name])
        except FileNotFoundError:
            return  # Supervisor can temporarily remove the path during rotation.
        opened_stat = os.fstat(file_handle.fileno())
        if (current_stat.st_dev, current_stat.st_ino) == (
            opened_stat.st_dev,
            opened_stat.st_ino,
        ):
            return
        replacement = open(self.log_files[process_name], "r", encoding="utf-8", errors="ignore")
        self.file_handles[process_name] = replacement
        file_handle.close()

    def start(self):
        """Start monitoring all log files."""
        print("[proc_logger] Starting process logger...", flush=True)

        # Open all log files
        self._open_log_files()

        # Start a thread for each log file
        threads = []
        for process_name in self.log_files:
            if process_name in self.file_handles:
                thread = threading.Thread(target=self._tail_file, args=(process_name,), daemon=True)
                thread.start()
                threads.append(thread)

        try:
            # Keep main thread alive
            while self.running:
                time.sleep(5)
        except KeyboardInterrupt:
            print("\n[proc_logger] Shutting down...", flush=True)
            self.stop()

    def stop(self):
        """Stop monitoring and close file handles."""
        self.running = False
        for file_handle in self.file_handles.values():
            try:
                file_handle.close()
            except Exception as e:
                print(f"[proc_logger] Error closing file handle: {e}", flush=True)


def main():
    """Main entry point."""
    # Define the log files to monitor
    log_files = {
        "nginx": "/var/log/supervisor/nginx.log",
        "cert-manager": "/var/log/supervisor/cert-manager.log",
    }

    # Create and start the logger
    logger = ProcessLogger(log_files)

    try:
        logger.start()
    except Exception as e:
        print(f"[proc_logger] Fatal error: {e}", flush=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
