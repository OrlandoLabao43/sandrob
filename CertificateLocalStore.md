# Introduction #

Having certificate file (.pfx, .p12) on SD card all the time in not save.
Every process has access to external storage.


# Details #

**SandroB** offer option to store certificate locally in his own database.

On input form is a check-box **local store**.

If checked certificate will be imported to database.
If unchecked on previous stored certificate, certificate will be deleted from database.

Store is encrypted with symmetric key which is generated from device id, user password and some random pre-generated salt.
After 3 failed attempts certificate is delete from the store.

There is some demonstration to test/check implementation:

http://code.google.com/p/sandrob/downloads/detail?name=sandrob_demo_1_0_0_10.apk

http://code.google.com/p/sandrob/source/browse/misc/KeyStoreUtils/src/org/sandrob/KeyStoreUtils/ExportImport.java

In addition to sqlite tables that comes with native browser, two more tables are added.

One to store ssl url info data and one to store certificate data.