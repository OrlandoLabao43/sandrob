# Browser with SSL client certificate support #


## Port of native android browser ##


---


<wiki:gadget url="http://google-code-feed-gadget.googlecode.com/svn/trunk/gadget.xml" up\_feeds="http://secureandroidbrowser.blogspot.com/atom.xml"  width="500" height="340" border="0"/>


Added support for client certificate.

Does not use global keystore.It uses local (in memory) until application is terminated.

After keystore is created pfx file can be removed.

Custom proxy can be specified in settings. (Menu->Settings->Enable Proxy)

### How to use it ###

Just input https url and pop-up will appear

asking you for certificate file and password.

If pop-up don't show up change
Menu->Settings->SSL dialog only on errors = OFF

When you are done click on Menu->Clear to invalidate SSL

### Versions: ###

**4.x**

There is no need for SandroB on 4.x android.
From 4.0.3 certificates works fine and even NTLM authentication is enabled.

There is sandroproxy that supports client certificates
if your version of OS is bellow 4.0.3

**3.x**

Not very secure solution

https://market.android.com/details?id=org.sandroproxy

**2.3.x, CM 7.1**

https://market.android.com/details?id=org.sandrob.stock233

https://market.android.com/details?id=org.sandrob.stock234

**2.2.x**

https://market.android.com/details?id=org.sandrob

**Cyanogenmod 6.1 and phones based on codeaurora sources**

https://market.android.com/details?id=org.sandrob.cm221

**2.1.x**

https://market.android.com/details?id=org.sandrob.stock211

**Cyanogenmod 7.0**


**removed from market (send mail if you need it)**

https://market.android.com/details?id=org.sandrob.cm233


---

**Warrning**

You should remove cert file after not needed any more.

It is not safe that you have it on the phone all the time.

Almost every process has access to <SD storage>/<your cert file>.


---

If you are looking how to implement SSL client authentication in your
application, check this example.

https://market.android.com/details?id=org.sandrob.sslexample


---

![http://3.bp.blogspot.com/-C-fNp5sjiHE/TpcucLt9NqI/AAAAAAAAABs/e_GVQg8iWos/s1600/sandrob_teaser_black_2.png](http://3.bp.blogspot.com/-C-fNp5sjiHE/TpcucLt9NqI/AAAAAAAAABs/e_GVQg8iWos/s1600/sandrob_teaser_black_2.png)