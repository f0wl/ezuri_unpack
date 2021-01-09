#include <stdio.h>

int main(int argc, char ** argv) {
  FILE * fp = fopen("/tmp/log.txt", "w+");
  while (1) {
    sleep(1);
    fprintf(fp, "Hey there! https://dissectingmalwa.re\n");
    fprintf(fp, "foobarbaz\n");
    fflush(fp);
  }
  fclose(fp);
  return 0;
} 
