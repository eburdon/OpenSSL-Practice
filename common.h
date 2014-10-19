/* 
 * 
 */

#include <stdarg.h>
#include <linux/random.h>
#include <fcntl.h>


// size of the buffer for incoming data
#define BUF_SIZE 1024


uint64_t modular_pow(uint64_t base, uint64_t exp, uint64_t modulus)
{

  base %= modulus;
  uint64_t result = 1;
  while (exp > 0) {
    if (exp & 1) result = (result * base) % modulus;
    base = (base * base) % modulus;
    exp >>= 1;
  }
  return result;
}

//
// send a string to the server. str is a "format" (similar to printf)
// that means you can do this:
//
//   send_string(socket, "This is my message %s", message);
//
// you can use any format that printf supports
// 
void send_string(int clientSocket, char *str,...)
{
  va_list ap;
  char buffer[BUF_SIZE*10];  // yeah
  int n;
  
  bzero(buffer, sizeof(buffer));

  va_start(ap, str);
  n = vsnprintf(buffer, sizeof(buffer), str, ap);
  va_end(ap);

  assert(n>=0);

  int len = strlen(buffer)+1;
  int lenSent;
  lenSent = send( clientSocket, buffer, len, 0 );
  if (lenSent != len) {
    perror("Could not send complete message");
    exit(1);
  }  
}
