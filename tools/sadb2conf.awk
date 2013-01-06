#!/usr/bin/awk -f


#Copyright (c) 2012-2013 Loïc Pefferkorn <loic-ipdecap@loicp.eu>
#ipdecap [http://www.loicp.eu/ipdecap]
#
#This file is part of ipdecap.
#
#Ipdecap is free software: you can redistribute it and/or modify
#it under the terms of the GNU General Public License as published by
#the Free Software Foundation, either version 3 of the License, or
#(at your option) any later version.
#
#Ipdecap is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.
#
#You should have received a copy of the GNU General Public License
#along with ipdecap.  If not, see <http://www.gnu.org/licenses/>.


# Convert setkey -Da output into an ipdecap ESP configuration file

BEGIN {
    FS="[() ]"
    entry=0
}

# Flow start
/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ [0-9]+\.[0-9]+\.[0-9]+\.[0-9]/ {
    src[entry]=$1
    dst[entry]=$2
}

/.*spi=/ {
    spi[entry]=$4
}

# Looking for encryption algorithm
/E: [^ ]+.*/ {

    if ($2 == "null")
      crypt[entry] = "null_enc"
    else
      if ($2 == "rijndael-cbc" )
        crypt[entry] = "aes128-cbc"
      else
        crypt[entry] = $2

      # Concat key without spaces
      key[entry]="0x"
      for (a=3;a<=NF;a++) {
        key[entry] = key[entry] $a
      }
}

# Looking for authentication algorithm
/A: [^ ]+.*/ {

    if ($2 == "null")
      auth[entry] = "null_auth"
    else
      if ($2 == "hmac-sha1")
        auth[entry] = "hmac_sha1-96"
      else
        if ($2 == "hmac-md5")
          auth[entry] = "hmac_md5-96"
        else
          auth[entry] = $2
}

# Dummy, increase number of entries found
/created:.*/  {
  entry += 1
}


END {
    # display each entry
    for(i=0;i<entry;i++)
      printf("%s\t%s\t%s\t%s\t%s\t%s\n", src[i], dst[i], crypt[i], auth[i], key[i], spi[i])
}
