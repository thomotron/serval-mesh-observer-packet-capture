/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   captureme.c
 * Author: honours
 *
 * Created on November 13, 2018, 5:53 PM
 */

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <unistd.h>
#include <termios.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

/*
 * 
 */

//Decodes hex values found in lbard's encoding system

//decode hex function pulled from lbard's util.c file
int hex_decode(char *in, unsigned char *out, int out_len, int radio_type)
{
  int retVal = -1;

  LOG_ENTRY;

  do 
  {
#if COMPILE_TEST_LEVEL >= TEST_LEVEL_LIGHT
    if (! in) 
    {
      LOG_ERROR("in is null");
      break;
    }
    if (! out) 
    {
      LOG_ERROR("out is null");
      break;
    }
    if (out_len > SENSIBLE_MEMORY_BLOCK_SIZE)
    {
      LOG_WARN("out_len seems a bit large: %d", out_len);
    }
    if (radio_type < RADIOTYPE_MIN || radio_type > RADIOTYPE_MAX)
    {
      LOG_WARN("radio_type out of range %d", radio_type);
    }
#endif

    int i;
    int out_count=0;

    int inLen = strlen(in);

    for (i = 0; i < inLen; i+=2) {
      int v = hextochar(in[i+0]) << 4;
      v |= hextochar(in[i+1]);
      out[out_count++] = v;
      if (out_count >= out_len) 
      {
       LOG_ERROR("trying to write more than out_len chars");
       break;//for
      }
    }
    out[out_count] = 0;
    retVal = out_count;
  }
  while (0);

  LOG_EXIT;

  return retVal;
}


int main(int argc, char **argv)
{
    int retVal = 0;

    do
    {
	//open file containing hex dump
	FILE *outFile = fopen("testFile", "r"); // read file
        
    } while (0);

    return (retVal);
}
