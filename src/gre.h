/*
  Copyright (c) 2012-2018 Loïc Pefferkorn <loic-ipdecap@loicp.eu>
  ipdecap [http://loicpefferkorn.net/ipdecap]

  This file is part of ipdecap.

  Ipdecap is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  Ipdecap is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with ipdecap.  If not, see <http://www.gnu.org/licenses/>.
*/

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
