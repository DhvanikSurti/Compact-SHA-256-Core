
`timescale 1ns/1ps

module tb_sha256;

    reg clk;
    reg rst_n;
    reg start;
    reg [511:0] block_in;
    wire [255:0] digest;
    wire digest_valid;

    // Instantiate DUT
    sha256_core uut (
        .clk(clk),
        .rst_n(rst_n),
        .start(start),
        .block_in(block_in),
        .digest(digest),
        .digest_valid(digest_valid)
    );

    // Clock generator (10ns = 100 MHz)
    always #5 clk = ~clk;

    initial begin
        $dumpfile("tb_sha256.vcd");
        $dumpvars(0, tb_sha256);

        clk = 0;
        rst_n = 0;
        start = 0;
        block_in = 512'd0;

        // Reset
        #20;
        rst_n = 1;

        // Load block for "abc"
        block_in = {
            32'h61626380, // "abc" + 0x80
            32'h00000000, // padding zeros
            32'h00000000,
            32'h00000000,
            32'h00000000,
            32'h00000000,
            32'h00000000,
            32'h00000000,
            32'h00000000,
            32'h00000000,
            32'h00000000,
            32'h00000000,
            32'h00000000,
            32'h00000000,
            32'h00000000,
            32'h00000018  // message length = 24 bits
        };

        // Start pulse
        #10 start = 1;
        #10 start = 0;

        // Wait until digest_valid
        wait (digest_valid);
        $display("Digest = %h", digest);

        // Expected:
        $display("Expected = BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD");

        #20;
        $finish;
    end

endmodule
