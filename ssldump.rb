class Ssldump < Formula
  desc "SSLv3/TLS network protocol analyzer"
  homepage "https://github.com/mathewmarcus/ssldump/tree/dh_aes_gcm_support"
  head "https://github.com/mathewmarcus/ssldump.git", :branch => "dh_aes_gcm_support"

  depends_on "openssl"

  patch :DATA

  def install
    ENV["LIBS"] = "-lssl -lcrypto"

    # .dylib, not .a
    inreplace "configure", "if test -f $dir/libpcap.a -o -f $dir/libpcap.so; then",
                           "if test -f $dir/libpcap.dylib; then"
    inreplace "configure", "ac_pcap_lib_dir=\"/usr/local/lib64 /usr/local/lib /usr/lib64 /usr/lib /usr/lib/x86_64-linux-gnu /usr/lib/i386-linux-gnu\"",
                            "ac_pcap_lib_dir=\"/usr/local/lib64 /usr/local/lib /usr/lib64 /usr/lib\""
    inreplace "configure", "ac_openssl_lib_dir=\"/usr/lib /usr/local /usr/local/ssl /usr/local/ssl/lib /usr/pkg /usr/lib/x86_64-linux-gnu /usr/lib/i386-linux-gnu\"",
                           "ac_openssl_lib_dir=\"/usr/lib /usr/local /usr/local/ssl /usr/local/ssl/lib /usr/pkg\""

    system "./configure", "--prefix=#{prefix}",
                          "--mandir=#{man}"
    system "make"
    # force install as make got confused by install target and INSTALL file.
    system "make", "install", "-B"
  end

  test do
    system "#{sbin}/ssldump", "-v"
  end
end

__END__
--- a/base/pcap-snoop.c
+++ b/base/pcap-snoop.c
@@ -47,6 +47,7 @@
 static char *RCSSTRING="$Id: pcap-snoop.c,v 1.14 2002/09/09 21:02:58 ekr Exp $";


+#include <net/bpf.h>
 #include <pcap.h>
 #include <unistd.h>
 #include <pcap-bpf.h>
--- a/ssl/ssl.enums.c
+++ b/ssl/ssl.enums.c
@@ -6,8 +6,32 @@
 #include <openssl/ssl.h>
 #endif
 #include "ssl.enums.h"
-static int decode_extension(ssl,dir,seg,data);
-static int decode_server_name(ssl,dir,seg,data);
+//static int decode_extension(ssl,dir,seg,data);
+static int decode_extension(ssl,dir,seg,data)
+  ssl_obj *ssl;
+  int dir;
+  segment *seg;
+  Data *data;
+  {
+    int l,r;
+    SSL_DECODE_UINT16(ssl,"extension length",0,data,&l);
+    data->len-=l;
+    data->data+=l;
+    return(0);
+  }
+//static int decode_server_name(ssl,dir,seg,data);
+static int decode_server_name(ssl,dir,seg,data)
+  ssl_obj *ssl;
+  int dir;
+  segment *seg;
+  Data *data;
+  {
+    int l,r;
+    SSL_DECODE_UINT16(ssl,"server name length",0,data,&l);
+    data->len-=l;
+    data->data+=l;
+    return(0);
+  }
 static int decode_ContentType_ChangeCipherSpec(ssl,dir,seg,data)
   ssl_obj *ssl;
   int dir;
@@ -2520,6 +2544,7 @@ static int decode_extension_extended_master_secret(ssl,dir,seg,data)
     *ems=dir==DIR_I2R?1:*ems==1;
     return(0);
   }
+/*
 static int decode_extension(ssl,dir,seg,data)
   ssl_obj *ssl;
   int dir;
@@ -2532,7 +2557,7 @@ static int decode_extension(ssl,dir,seg,data)
     data->data+=l;
     return(0);
   }
-
+*/
 
 decoder extension_decoder[] = {
 	{
@@ -2610,6 +2635,7 @@ static int decode_server_name_type_host_name(ssl,dir,seg,data)
     data->data+=l;
     return(0);
   }
+/*
 static int decode_server_name(ssl,dir,seg,data)
   ssl_obj *ssl;
   int dir;
@@ -2622,7 +2648,7 @@ static int decode_server_name(ssl,dir,seg,data)
     data->data+=l;
     return(0);
   }
-
+*/
 decoder server_name_type_decoder[]={
 	{
 		0,
