#include <tunables/global>
profile neonsec flags=(attach_disconnected) {
  #include <abstractions/base>
  /neonsec rix,
  capability chown,
  deny network,
}
