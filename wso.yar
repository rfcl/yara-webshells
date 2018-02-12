rule wso_generic : webshell
{

  meta:
    author = "rfcl"
    description = "Detects web shells in the WSO family."

  strings:
    $magic_numbers = { 3c 3f 70 68 70 }
    $exploit_db = "http://noreferer.de/?http://www.exploit-db.com/search/?action=search&description="
    $base64_str1 = "U2VydmVyOiA8aW5wdXQgdHlwZT0ndGV4dCcgbmFtZT0nc2VydmVyJyB2YWx1ZT0nPD89JF9TRVJWRVJbJ1JFTU9URV9BRERSJ10/Pic+IFBvcnQ6IDxpbnB1dCB0eXBlPSd0ZXh0JyBuYW1lPSdwb3J0JyB2YWx1ZT0nMzEzMzcnPiBVc2luZzogPHNlbGVjdCBuYW1lPSJ1c2luZyI+PG9wdGlvbiB2YWx1ZT0nYmNjJz5DPC9vcHRpb24+PG9wdGlvbiB2YWx1ZT0nYmNwJz5QZXJsPC9vcHRpb24+PC9zZWxlY3Q+IDxpbnB1dCB0eXBlPXN1Ym1pdCB2YWx1ZT0iPj4iPg"
    $safe_mode1 = "safe_mode_exec_dir"
    $safe_mode2 = "safe_mode_include_dir"
    $secParam = "showSecParam"

  condition:
    $magic_numbers
    and ($secParam and 1 of ($safe_mode*)
    or 1 of ($exploit_db, $base64_str1))
}
