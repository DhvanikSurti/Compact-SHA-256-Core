# Compact-SHA-256-Core
This project implements a compact SHA-256 core on FPGA, optimized to fit within 15K LUT4 and operate at 15 MHz. Using a 10-cycle pipeline, it processes a 512-bit block and outputs a 256-bit digest. Modules include message scheduler, compression core, and digest generator, verified with FIPS test vectors.
