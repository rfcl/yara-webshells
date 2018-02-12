rule c99_generic : webshell
{
  meta:
    author = "rfcl"
    description = "Generic rule to detect web shells in the c99 family"

  strings:
    $magic_numbers = { 3c 3f 70 68 70 }
    $shellfind1 = "array(\"-----------------------------------------------------------\", \"ls -la\"),"
    $shellfind2 = "array(\"find all suid files\", \"find / -type f -perm -04000 -ls\"),"
    $shellfind3 = "array(\"find suid files in current dir\", \"find . -type f -perm -04000 -ls\"),"
    $shellfind4 = "array(\"find all sgid files\", \"find / -type f -perm -02000 -ls\"),"
    $shellfind5 = "array(\"find sgid files in current dir\", \"find . -type f -perm -02000 -ls\"),"
    $shellfind6 = "array(\"find config.inc.php files\", \"find / -type f -name config.inc.php\"),"
    $shellfind7 = "array(\"find config* files\", \"find / -type f -name \\\"config*\\\"\"),"
    $menu1      = "act=ftpquickbrute&d=%d"
    $menu2      = "act=selfremove"

  condition:
    $magic_numbers and
    (
      any of ($shellfind*)
      and any of ($menu*)
    )
}
