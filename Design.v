module sha256_core(
    input wire clk,
    input wire rst_n,
    input wire start,
    input wire [511:0] block_in,
    output reg [255:0] digest,
    output reg digest_valid
);

    parameter H0_IV = 32'h6a09e667, H1_IV = 32'hbb67ae85;
    parameter H2_IV = 32'h3c6ef372, H3_IV = 32'ha54ff53a;
    parameter H4_IV = 32'h510e527f, H5_IV = 32'h9b05688c;    
    parameter H6_IV = 32'h1f83d9ab, H7_IV = 32'h5be0cd19;

    parameter S_IDLE=2'd0, S_LOAD=2'd1, S_RUN=2'd2, S_FIN=2'd3;
    reg [1:0] state, nxt_state;
    reg [5:0] tbase, nxt_tbase;

    reg [31:0] a,b,c,d,e,f,g,h;
    reg [31:0] an,bn,cn,dn,en,fn,gn,hn;

    reg [31:0] H0,H1,H2,H3,H4,H5,H6,H7;

    reg [511:0] win, win_nxt;

    wire [255:0] W_flat;
    wire [511:0] win_out;
    wire [255:0] K_flat;

    wire [31:0] a8,b8,c8,d8,e8,f8,g8,h8;

    sha256_msg_sched8 sched_inst(
        .win_in(win),
        .W_flat(W_flat),
        .win_out(win_out)
    );

    sha256_krom8 krom_inst(
        .tbase(tbase),
        .K_flat(K_flat)
    );

    sha256_round8 round_inst(
        .a_in(a),.b_in(b),.c_in(c),.d_in(d),
        .e_in(e),.f_in(f),.g_in(g),.h_in(h),
        .W_flat(W_flat),.K_flat(K_flat),
        .a_out(a8),.b_out(b8),.c_out(c8),.d_out(d8),
        .e_out(e8),.f_out(f8),.g_out(g8),.h_out(h8)
    );

    integer i;
    always @* begin
        nxt_state = state;
        nxt_tbase = tbase;
        digest_valid = 1'b0;
        an=a; bn=b; cn=c; dn=d; en=e; fn=f; gn=g; hn=h;
        win_nxt=win;

        case(state)
            S_IDLE: if(start) nxt_state = S_LOAD;

            S_LOAD: begin
                nxt_state = S_RUN;
                nxt_tbase = 6'd0;
                an=H0_IV; bn=H1_IV; cn=H2_IV; dn=H3_IV;
                en=H4_IV; fn=H5_IV; gn=H6_IV; hn=H7_IV;
                for(i=0;i<16;i=i+1)
                    win_nxt[511-32*i -:32] = block_in[511-32*i -:32];
            end

            S_RUN: begin
                an=a8; bn=b8; cn=c8; dn=d8;
                en=e8; fn=f8; gn=g8; hn=h8;
                for(i=0;i<16;i=i+1)
                    win_nxt[511-32*i -:32] = win_out[511-32*i -:32];
                if(tbase==6'd56) nxt_state=S_FIN;
                else nxt_tbase = tbase+6'd8;
            end

            S_FIN: begin
                digest_valid=1'b1;
                nxt_state=S_IDLE;
            end
        endcase
    end

    always @(posedge clk or negedge rst_n) begin
        if(!rst_n) begin
            state<=S_IDLE; tbase<=0;
            {a,b,c,d,e,f,g,h}<=0;
            {H0,H1,H2,H3,H4,H5,H6,H7}<=0;
            digest<=0; win<=0;
        end else begin
            state<=nxt_state; tbase<=nxt_tbase;
            a<=an; b<=bn; c<=cn; d<=dn;
            e<=en; f<=fn; g<=gn; h<=hn;
            win<=win_nxt;
            if(state==S_LOAD) begin
                H0<=H0_IV; H1<=H1_IV; H2<=H2_IV; H3<=H3_IV;
                H4<=H4_IV; H5<=H5_IV; H6<=H6_IV; H7<=H7_IV;
            end
            if(state==S_FIN) begin
                digest <= {H0+a,H1+b,H2+c,H3+d,H4+e,H5+f,H6+g,H7+h};
            end
        end
    end
endmodule

module sha256_round8(
    input wire [31:0] a_in,b_in,c_in,d_in,
    input wire [31:0] e_in,f_in,g_in,h_in,
    input wire [255:0] W_flat,
    input wire [255:0] K_flat,
    output reg [31:0] a_out,b_out,c_out,d_out,
    output reg [31:0] e_out,f_out,g_out,h_out
);
    wire [31:0] W[0:7]; wire [31:0] K[0:7];
    genvar i;
    generate
        for(i=0;i<8;i=i+1) begin: unpack
            assign W[i]=W_flat[255-32*i -:32];
            assign K[i]=K_flat[255-32*i -:32];
        end
    endgenerate

    function [31:0] ROTR; input [31:0] x; input integer n;
        begin ROTR=(x>>n)|(x<<(32-n)); end
    endfunction
    function [31:0] Ch; input [31:0] x,y,z;
        begin Ch=(x&y)^(~x&z); end
    endfunction
    function [31:0] Maj; input [31:0] x,y,z;
        begin Maj=(x&y)^(x&z)^(y&z); end
    endfunction
    function [31:0] S0; input [31:0] x;
        begin S0=ROTR(x,2)^ROTR(x,13)^ROTR(x,22); end
    endfunction
    function [31:0] S1; input [31:0] x;
        begin S1=ROTR(x,6)^ROTR(x,11)^ROTR(x,25); end
    endfunction

    integer j;
    reg [31:0] a,b,c,d,e,f,g,h,T1,T2;
    always @* begin
        a=a_in; b=b_in; c=c_in; d=d_in;
        e=e_in; f=f_in; g=g_in; h=h_in;
        for(j=0;j<8;j=j+1) begin
            T1=h+S1(e)+Ch(e,f,g)+K[j]+W[j];
            T2=S0(a)+Maj(a,b,c);
            h=g; g=f; f=e; e=d+T1;
            d=c; c=b; b=a; a=T1+T2;
        end
        a_out=a; b_out=b; c_out=c; d_out=d;
        e_out=e; f_out=f; g_out=g; h_out=h;
    end
endmodule

module sha256_msg_sched8(
    input wire [511:0] win_in,
    output wire [255:0] W_flat,
    output wire [511:0] win_out
);
    function [31:0] ROTR; input [31:0] x; input integer n;
        begin ROTR=(x>>n)|(x<<(32-n)); end
    endfunction
    function [31:0] SHR; input [31:0] x; input integer n;
        begin SHR=x>>n; end
    endfunction
    function [31:0] s0; input [31:0] x;
        begin s0=ROTR(x,7)^ROTR(x,18)^SHR(x,3); end
    endfunction
    function [31:0] s1; input [31:0] x;
        begin s1=ROTR(x,17)^ROTR(x,19)^SHR(x,10); end
    endfunction

    wire [31:0] tmp[0:23];
    genvar i;
    generate
        for(i=0;i<16;i=i+1) assign tmp[i]=win_in[511-32*i -:32];
        for(i=16;i<24;i=i+1) assign tmp[i]=s1(tmp[i-2])+tmp[i-7]+s0(tmp[i-15])+tmp[i-16];
        for(i=0;i<8;i=i+1) assign W_flat[255-32*i -:32]=tmp[i];
        for(i=0;i<16;i=i+1) assign win_out[511-32*i -:32]=tmp[8+i];
    endgenerate
endmodule

module sha256_krom8(
    input wire [5:0] tbase,
    output wire [255:0] K_flat
);
    reg [31:0] K[0:63];
    integer i;
    initial begin
        K[0]=32'h428a2f98; K[1]=32'h71374491; K[2]=32'hb5c0fbcf; K[3]=32'he9b5dba5;
        K[4]=32'h3956c25b; K[5]=32'h59f111f1; K[6]=32'h923f82a4; K[7]=32'hab1c5ed5;
        K[8]=32'hd807aa98; K[9]=32'h12835b01; K[10]=32'h243185be; K[11]=32'h550c7dc3;
        K[12]=32'h72be5d74; K[13]=32'h80deb1fe; K[14]=32'h9bdc06a7; K[15]=32'hc19bf174;
        K[16]=32'he49b69c1; K[17]=32'hefbe4786; K[18]=32'h0fc19dc6; K[19]=32'h240ca1cc;
        K[20]=32'h2de92c6f; K[21]=32'h4a7484aa; K[22]=32'h5cb0a9dc; K[23]=32'h76f988da;
        K[24]=32'h983e5152; K[25]=32'ha831c66d; K[26]=32'hb00327c8; K[27]=32'hbf597fc7;
        K[28]=32'hc6e00bf3; K[29]=32'hd5a79147; K[30]=32'h06ca6351; K[31]=32'h14292967;
        K[32]=32'h27b70a85; K[33]=32'h2e1b2138; K[34]=32'h4d2c6dfc; K[35]=32'h53380d13;
        K[36]=32'h650a7354; K[37]=32'h766a0abb; K[38]=32'h81c2c92e; K[39]=32'h92722c85;
        K[40]=32'ha2bfe8a1; K[41]=32'ha81a664b; K[42]=32'hc24b8b70; K[43]=32'hc76c51a3;
        K[44]=32'hd192e819; K[45]=32'hd6990624; K[46]=32'hf40e3585; K[47]=32'h106aa070;
        K[48]=32'h19a4c116; K[49]=32'h1e376c08; K[50]=32'h2748774c; K[51]=32'h34b0bcb5;
        K[52]=32'h391c0cb3; K[53]=32'h4ed8aa4a; K[54]=32'h5b9cca4f; K[55]=32'h682e6ff3;
        K[56]=32'h748f82ee; K[57]=32'h78a5636f; K[58]=32'h84c87814; K[59]=32'h8cc70208;
        K[60]=32'h90befffa; K[61]=32'ha4506ceb; K[62]=32'hbef9a3f7; K[63]=32'hc67178f2;
    end

    genvar j;
    generate
        for(j=0;j<8;j=j+1)
            assign K_flat[255-32*j -:32]=K[tbase+j];
    endgenerate
endmodule
