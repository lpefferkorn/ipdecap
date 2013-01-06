
// http://tools.ietf.org/html/rfc1701

struct grehdr {
  u_int16_t flags;
  u_int16_t next_protocol;
  } __attribute((packed));


#define GRE_CHECKSUM 0x8000
#define GRE_ROUTING  0x4000
#define GRE_KEY      0x2000
#define GRE_SEQ      0x1000
#define GRE_SSRCR    0x0800
