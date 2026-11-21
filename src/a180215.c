/* A180215 -- exact ordered weighted-window permutation counter.
 * Maintained for Carlo Corti. Fixed kernel (1,4,6,4,1), serial C17 + U128.
 * Each admissible outward word contributes BEFORE continuation filtering.
 * The zero-anchor bijection gives sum F[S]F[U\S]. Reduction below uses
 * twice one representative of every complementary pair, never a quotient.
 * Build: make -C src. Linux, 64-bit size_t/off_t, OpenSSL EVP SHA256.
 * init ROOT N; next ROOT SECONDS; status ROOT; audit ROOT; selftest.
 * N=1..32 is structural scope, NOT campaign authority. Exit75 is partial.
 * Binary formats use explicit LE integers, never padded native structs.
 * walk.bin: repeated 2048-byte headers, <=2^20 LE32 events, SHA256 trailer.
 * Header: magic[8], events32, phase32, N32, depth32, seq64, nodes64,
 * m32, reserved32, scan64, reserved64, 32 U128 answers at64;
 * 32 frames at576 (mask,remaining,a,b,c,d,mode,reserved : eight LE32);
 * cfg SHA at1600, predecessor SHA at1632, final F SHA at1664; rest zero.
 * ENTER=0, SCAN=1, RETURN=2. Phases WALK=0, REDUCE=1, PRODUCED=2.
 * Complete bad frames always fail closed. Only an incomplete EOF transaction
 * after a committed frame, with valid available header fields, is discardable
 * on explicit next; status/audit never truncate. SHA is integrity, not proof.
 * F is scratch during WALK; after REDUCE admission its SHA is immutable.
 * Recovery from WALK replays ALL committed mask events into zeroed F.
 * next locks the directory; no automatic retries, subprocesses or target step.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <openssl/evp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#if !defined(__SIZEOF_INT128__) || __SIZEOF_INT128__ != 16
#error unsigned128 support required
#endif
__extension__ typedef unsigned __int128 U128;
_Static_assert(sizeof(size_t) == 8 && sizeof(off_t) == 8, "64-bit host required");
enum { H = 2048, Q = 1048576, WALK = 0, REDUCE = 1, PRODUCED = 2 };
#define DISK_CAP (UINT64_C(64) << 30)
#define RSS_CAP (UINT64_C(48) << 30)
typedef struct { uint32_t mask, rem, a, b, c, d, mode; } Frame;
typedef struct {
    uint32_t n, phase, depth, m;
    uint64_t seq, nodes, scan;
    U128 ans[32]; Frame stack[32];
    unsigned char fsha[32];
} State;
static int rootfd = -1;
static unsigned char cfgsha[32];
static volatile sig_atomic_t stopped;
static double started, deadline, lastbeat;
static unsigned seconds_limit;
static unsigned telemetry_n;
static void fail(const char *s) { fprintf(stderr, "ERROR: %s (%s)\n", s, strerror(errno)); exit(2); }
static void require(bool b, const char *s) { if (!b) { errno = EINVAL; fail(s); } }
static uint64_t number(const char *s, uint64_t max) {
    uint64_t x = 0;
    require(*s != '\0', "empty integer");
    for (; *s; ++s) { require(*s >= '0' && *s <= '9', "unsigned decimal required");
        unsigned d = (unsigned)(*s - '0'); require(d <= max && x <= (max - d) / 10, "integer range"); x = x * 10 + d; }
    return x;
}
static double now(void) { struct timespec t; if (clock_gettime(CLOCK_MONOTONIC, &t)) fail("clock"); return (double)t.tv_sec + (double)t.tv_nsec / 1e9; }
static void io_progress(const char *phase,uint64_t processed,bool force) {
    double t=now();if(force||t-lastbeat>=5){struct rusage r;if(getrusage(RUSAGE_SELF,&r))fail("rusage");char n[16];if(telemetry_n)(void)snprintf(n,sizeof n,"%u",telemetry_n);else strcpy(n,"UNKNOWN");fprintf(stderr,"N=%s phase=%s processed_bytes=%" PRIu64 " durability=UNCOMMITTED_OR_READ_ONLY elapsed=%.3f invocation_budget=%u peak_RSS_bytes=%" PRIu64 " ETA=UNKNOWN stop=RUNNING\n",n,phase,processed,t-started,seconds_limit,(uint64_t)r.ru_maxrss*1024);lastbeat=t;}
}
static void handler(int s) { (void)s; stopped = 1; }
static void put(unsigned char *p, uint64_t x, unsigned k) { for (unsigned i=0;i<k;++i) { p[i]=(unsigned char)x; x>>=8; } }
static uint64_t get(const unsigned char *p, unsigned k) { uint64_t x=0; for (unsigned i=k;i>0;--i) x=(x<<8)|p[i-1]; return x; }
static void put128(unsigned char *p,U128 x) { put(p,(uint64_t)x,8); put(p+8,(uint64_t)(x>>64),8); }
static U128 get128(const unsigned char *p) { return (U128)get(p,8)|((U128)get(p+8,8)<<64); }
static U128 add(U128 a,U128 b) { require(a <= ~(U128)0-b,"U128 addition"); return a+b; }
static U128 mul(U128 a,U128 b) { require(!a || b <= ~(U128)0/a,"U128 multiplication"); return a*b; }
static void decimal(U128 x,char out[40]) { char tmp[40]; unsigned k=0; do { tmp[k++]=(char)('0'+x%10); x/=10; } while(x); for(unsigned i=0;i<k;++i)out[i]=tmp[k-1-i];out[k]=0; }
static void hex(const unsigned char *p,char out[65]) { static const char h[]="0123456789abcdef"; for(unsigned i=0;i<32;++i){out[2*i]=h[p[i]>>4];out[2*i+1]=h[p[i]&15];}out[64]=0; }
static EVP_MD_CTX *digest(void) { EVP_MD_CTX *c=EVP_MD_CTX_new(); require(c!=NULL,"EVP context"); require(EVP_DigestInit_ex(c,EVP_sha256(),NULL)==1,"EVP init"); return c; }
static void update(EVP_MD_CTX *c,const void *p,size_t n) { require(EVP_DigestUpdate(c,p,n)==1,"EVP update"); }
static void finish(EVP_MD_CTX *c,unsigned char h[32]) { unsigned k=0; require(EVP_DigestFinal_ex(c,h,&k)==1 && k==32,"EVP final"); EVP_MD_CTX_free(c); }
static void writeall(int fd,const void *vp,size_t n) { const unsigned char *p=vp; while(n){ssize_t k=write(fd,p,n);if(k<0&&errno==EINTR)continue;if(k<=0)fail("write");p+=(size_t)k;n-=(size_t)k;} }
static void readall(int fd,void *vp,size_t n) { unsigned char *p=vp; while(n){ssize_t k=read(fd,p,n);if(k<0&&errno==EINTR)continue;if(k<=0)fail("short read");p+=(size_t)k;n-=(size_t)k;} }
static uint64_t length(int fd) { struct stat st; if(fstat(fd,&st))fail("stat"); require(S_ISREG(st.st_mode)&&st.st_nlink==1&&st.st_size>=0,"regular unlinked-safe file required");return(uint64_t)st.st_size; }
static int openfile(const char *name,int flags) { int fd=openat(rootfd,name,flags|O_NOFOLLOW|O_CLOEXEC,0600);if(fd<0)fail(name);return fd; }
static void syncfd(int fd) { if(fsync(fd))fail("fsync"); }
static void closefd(int fd) { if(close(fd))fail("close"); }
static void syncparent(const char *root) {
    char p[PATH_MAX];require(realpath(root,p)!=NULL,"root realpath");char *slash=strrchr(p,'/');require(slash!=NULL,"root parent");if(slash==p)slash[1]=0;else *slash=0;
    int fd=open(p,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(fd<0)fail("parent directory");syncfd(fd);closefd(fd);
}
static void hashfd(int fd,unsigned char h[32]) { unsigned char b[262144];uint64_t bytes=0;EVP_MD_CTX *c=digest();if(lseek(fd,0,SEEK_SET)<0)fail("seek");for(;;){ssize_t k=read(fd,b,sizeof b);if(k<0&&errno==EINTR)continue;if(k<0)fail("digest read");if(!k)break;update(c,b,(size_t)k);bytes+=(uint64_t)k;io_progress("HASH_READ",bytes,false);}finish(c,h); }
static void hashpath(const char *p,unsigned char h[32]) { int fd=open(p,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);if(fd<0)fail(p);(void)length(fd);hashfd(fd,h);closefd(fd); }
static uint64_t fbytes(unsigned n) { require(n>=1&&n<=32,"N must be1..32");return UINT64_C(16)<<(n-1); }
static bool exists(const char *s) { struct stat st;if(fstatat(rootfd,s,&st,AT_SYMLINK_NOFOLLOW)==0)return true;if(errno!=ENOENT)fail("exists");return false; }
static uint64_t rootbytes(void) {
    static const char *const names[]={"cfg.json","walk.bin","f.bin","check.bin","val.tsv","res.tsv","done.json","txn1.tmp","txn2.tmp"};
    int dfd=openat(rootfd,".",O_RDONLY|O_DIRECTORY|O_CLOEXEC);if(dfd<0)fail("directory");DIR *d=fdopendir(dfd);if(!d)fail("opendir");uint64_t total=0;struct dirent *e;
    errno=0;while((e=readdir(d))){if(!strcmp(e->d_name,".")||!strcmp(e->d_name,".."))continue;bool ok=false;for(unsigned i=0;i<9;++i)if(!strcmp(e->d_name,names[i]))ok=true;require(ok,"unexpected root entry");int fd=openfile(e->d_name,O_RDONLY);uint64_t k=length(fd);closefd(fd);require(k<=DISK_CAP-total,"root storage quota");total+=k;errno=0;}if(errno)fail("readdir");if(closedir(d))fail("closedir");return total;
}
static void quota(uint64_t extra) { uint64_t used=rootbytes();require(extra<=DISK_CAP-used,"scratch quota before mutation"); }
static void rootopen(const char *p,bool write_mode) { rootfd=open(p,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(rootfd<0)fail("root");if(flock(rootfd,(write_mode?LOCK_EX:LOCK_SH)|LOCK_NB))fail("root busy");(void)rootbytes(); }
static unsigned config(unsigned n,bool fresh) {
    char exe[PATH_MAX],p[PATH_MAX];ssize_t k=readlink("/proc/self/exe",exe,sizeof exe-1);require(k>0&&(size_t)k<sizeof exe-1,"executable path");exe[k]=0;
    unsigned char sh[32],mh[32],bh[32],lh[32];char s[65],m[65],b[65],l[65];hashpath(exe,bh);char *slash=strrchr(exe,'/');require(slash!=NULL,"source neighborhood");*slash=0;
    int z=snprintf(p,sizeof p,"%s/a180215.c",exe);require(z>0&&(size_t)z<sizeof p,"source path");hashpath(p,sh);
    z=snprintf(p,sizeof p,"%s/Makefile",exe);require(z>0&&(size_t)z<sizeof p,"makefile path");hashpath(p,mh);
    Dl_info info;void *symbol=dlsym(RTLD_DEFAULT,"EVP_DigestInit_ex");require(symbol&&dladdr(symbol,&info)&&info.dli_fname,"crypto location");
    require(realpath(info.dli_fname,p)!=NULL,"crypto realpath");hashpath(p,lh);hex(sh,s);hex(mh,m);hex(bh,b);hex(lh,l);
    char actual[1024],expected[1024];size_t count=0;
    if(!fresh){int fd=openfile("cfg.json",O_RDONLY);uint64_t sz=length(fd);require(sz<sizeof actual,"cfg size");count=(size_t)sz;readall(fd,actual,count);actual[count]=0;closefd(fd);const char prefix[]="{\"schema\":1,\"N\":";require(!strncmp(actual,prefix,sizeof prefix-1),"cfg grammar");char *end=strchr(actual+sizeof prefix-1,',');require(end!=NULL,"cfg N delimiter");char saved=*end;*end=0;n=(unsigned)number(actual+sizeof prefix-1,32);*end=saved;}
    (void)fbytes(n);
    z=snprintf(expected,sizeof expected,"{\"schema\":1,\"N\":%u,\"source\":\"%s\",\"makefile\":\"%s\",\"binary\":\"%s\",\"crypto\":\"%s\"}\n",n,s,m,b,l);require(z>0&&(size_t)z<sizeof expected,"cfg encoding");
    if(fresh){int fd=openfile("cfg.json",O_WRONLY|O_CREAT|O_EXCL);writeall(fd,expected,(size_t)z);syncfd(fd);closefd(fd);syncfd(rootfd);}
    else require(count==(size_t)z&&!memcmp(actual,expected,count),"config/build/source/dependency mismatch");
    EVP_MD_CTX *c=digest();update(c,expected,(size_t)z);finish(c,cfgsha);return n;
}
static uint32_t available(const Frame *f,unsigned n) { unsigned base=f->a+4*f->b+6*f->c+4*f->d;unsigned M=n-1;if(base>M)return 0;unsigned lo=base>1?base:1;uint32_t all=(UINT32_C(1)<<M)-1;return all&~f->mask&~((UINT32_C(1)<<(lo-1))-1); }
static void validate(const State *s) {
    require(s->n>=1&&s->n<=32&&s->phase<=PRODUCED&&s->depth<=s->n,"state domain");
    uint32_t all=(UINT32_C(1)<<(s->n-1))-1;
    if(s->phase==WALK)require(s->depth>=1,"walk depth");else require(s->depth==0,"closed stack");
    for(unsigned i=0;i<s->depth;++i){const Frame *f=&s->stack[i];require(!(f->mask&~all)&&f->a<s->n&&f->b<s->n&&f->c<s->n&&f->d<s->n&&f->mode<=2,"frame domain");require((unsigned)__builtin_popcount(f->mask)==i,"stack cardinality");require(!(f->rem&~available(f,s->n)),"child cursor subset");if(i==0)require(!f->mask&&!f->a&&!f->b&&!f->c&&!f->d,"empty root");else {const Frame *p=&s->stack[i-1];uint32_t bit=f->mask^p->mask;require(bit&&!(bit&(bit-1))&&!(bit&p->mask),"stack edge");unsigned v=(unsigned)__builtin_ctz(bit)+1;unsigned base=p->a+4*p->b+6*p->c+4*p->d;require(v>=base&&f->a==p->b&&f->b==p->c&&f->c==p->d&&f->d==v-base&&p->mode==1,"stack coordinates");}}
    require(s->m>=1&&s->m<=s->n,"reduction dimension");if(s->phase==REDUCE){require(s->m<s->n,"reduction range");require(s->scan<(UINT64_C(1)<<(s->m-1)),"reduction cursor");}
}
static void encode(unsigned char h[H],const State *s,unsigned count,const unsigned char prev[32]) {
    memset(h,0,H);memcpy(h,"A215WALK",8);put(h+8,count,4);put(h+12,s->phase,4);put(h+16,s->n,4);put(h+20,s->depth,4);put(h+24,s->seq,8);put(h+32,s->nodes,8);put(h+40,s->m,4);put(h+48,s->scan,8);
    for(unsigned i=0;i<32;++i){put128(h+64+16*i,s->ans[i]);const Frame *f=&s->stack[i];unsigned char *p=h+576+32*i;if(i<s->depth){put(p,f->mask,4);put(p+4,f->rem,4);put(p+8,f->a,4);put(p+12,f->b,4);put(p+16,f->c,4);put(p+20,f->d,4);put(p+24,f->mode,4);}}
    memcpy(h+1600,cfgsha,32);memcpy(h+1632,prev,32);memcpy(h+1664,s->fsha,32);
}
static State decode(const unsigned char h[H]) { State s={0};s.phase=(uint32_t)get(h+12,4);s.n=(uint32_t)get(h+16,4);s.depth=(uint32_t)get(h+20,4);s.seq=get(h+24,8);s.nodes=get(h+32,8);s.m=(uint32_t)get(h+40,4);s.scan=get(h+48,8);for(unsigned i=0;i<32;++i){s.ans[i]=get128(h+64+16*i);Frame *f=&s.stack[i];const unsigned char *p=h+576+32*i;f->mask=(uint32_t)get(p,4);f->rem=(uint32_t)get(p+4,4);f->a=(uint32_t)get(p+8,4);f->b=(uint32_t)get(p+12,4);f->c=(uint32_t)get(p+16,4);f->d=(uint32_t)get(p+20,4);f->mode=(uint32_t)get(p+24,4);}memcpy(s.fsha,h+1664,32);validate(&s);return s; }
static uint64_t journal(int fd,unsigned n,State *s,unsigned char prev[32],U128 *F) {
    uint64_t sz=length(fd),pos=0,seq=0,nodes=0;unsigned oldphase=0;unsigned char h[H],re[H],b[262144],got[32],hash[32];memset(prev,0,32);if(lseek(fd,0,SEEK_SET)<0)fail("journal seek");
    while(pos<sz){uint64_t left=sz-pos;if(left<H){readall(fd,h,(size_t)left);require(seq>0&&!memcmp(h,"A215WALK",left<8?(size_t)left:8),"torn header prefix");if(left>=12)require(get(h+8,4)<=Q,"torn header count");if(left>=20)require(get(h+16,4)==n,"torn header N");if(left>=32)require(get(h+24,8)==seq,"torn header sequence");if(left>=1632)require(!memcmp(h+1600,cfgsha,32),"torn header cfg");if(left>=1664)require(!memcmp(h+1632,prev,32),"torn header chain");return pos;}
        readall(fd,h,H);require(!memcmp(h,"A215WALK",8),"journal magic");unsigned count=(unsigned)get(h+8,4);require(count<=Q,"journal block bound");State t=decode(h);require(t.n==n&&t.seq==seq&&t.nodes==nodes+count&&t.phase>=oldphase,"journal ordering");encode(re,&t,count,prev);require(!memcmp(h,re,H),"journal header/identity/canonical encoding");uint64_t size=H+4*(uint64_t)count+32;if(size>left){require(seq>0,"incomplete initial commit");return pos;}
        EVP_MD_CTX *c=digest();update(c,h,H);uint64_t remain=4*(uint64_t)count;while(remain){size_t take=remain>sizeof b?sizeof b:(size_t)remain;readall(fd,b,take);update(c,b,take);for(size_t j=0;j<take;j+=4){uint32_t mask=(uint32_t)get(b+j,4);require(mask<(UINT64_C(1)<<(n-1)),"event mask");if(F)F[mask]=add(F[mask],1);}remain-=take;io_progress(F?"JOURNAL_REPLAY":"JOURNAL_AUDIT",pos+H+4*(uint64_t)count-remain,false);}finish(c,hash);readall(fd,got,32);require(!memcmp(hash,got,32),"journal digest");memcpy(prev,hash,32);*s=t;nodes=t.nodes;oldphase=t.phase;++seq;pos+=size;
    }require(seq>0,"empty journal");return pos;
}
static void commit(int fd,State *s,unsigned char prev[32],const uint32_t *events,unsigned count) {
    validate(s);unsigned char h[H],b[262144],hash[32];encode(h,s,count,prev);quota(H+4*(uint64_t)count+32+(s->phase==WALK?fbytes(s->n):0));EVP_MD_CTX *c=digest();update(c,h,H);writeall(fd,h,H);unsigned i=0;while(i<count){unsigned take=count-i;if(take>sizeof b/4)take=sizeof b/4;for(unsigned j=0;j<take;++j)put(b+4*j,events[i+j],4);update(c,b,4*(size_t)take);writeall(fd,b,4*(size_t)take);i+=take;}finish(c,hash);writeall(fd,hash,32);syncfd(fd);memcpy(prev,hash,32);require(s->seq<UINT64_MAX,"sequence next step");++s->seq;
}
static void beat(const State *s,const char *reason,bool force) { double t=now();if(force||t-lastbeat>=5){struct rusage r;if(getrusage(RUSAGE_SELF,&r))fail("rusage");fprintf(stderr,"N=%u phase=%s committed_events=%" PRIu64 " m=%u scan=%" PRIu64 " elapsed=%.3f invocation_budget=%u peak_RSS_bytes=%" PRIu64 " root_bytes=%" PRIu64 " remaining_tree=UNKNOWN ETA=UNKNOWN stop=%s\n",s->n,s->phase==WALK?"WALK":s->phase==REDUCE?"REDUCE":"PRODUCED_UNVERIFIED",s->nodes,s->m,s->scan,t-started,seconds_limit,(uint64_t)r.ru_maxrss*1024,rootbytes(),reason);lastbeat=t;} }
static void discard(const char *p) { if(unlinkat(rootfd,p,0)&&errno!=ENOENT)fail("discard uncommitted transaction");syncfd(rootfd); }
static void textfile(const char *name,const char *p,size_t k) {
    if(exists(name)){int fd=openfile(name,O_RDONLY);require(length(fd)==k,"existing output size conflict");char *b=malloc(k?k:1);require(b!=NULL,"text read buffer");readall(fd,b,k);require(!memcmp(p,b,k),"existing output content conflict");free(b);closefd(fd);return;}
    quota(k);int fd=openfile("txn1.tmp",O_WRONLY|O_CREAT|O_EXCL);writeall(fd,p,k);syncfd(fd);closefd(fd);if(renameat(rootfd,"txn1.tmp",rootfd,name))fail("publish text");syncfd(rootfd);
}
static void saveF(const U128 *F,unsigned n,unsigned char sha[32]) {
    unsigned char b[262144];uint64_t cells=UINT64_C(1)<<(n-1);quota(fbytes(n));int fd=openfile("txn1.tmp",O_WRONLY|O_CREAT|O_EXCL);EVP_MD_CTX *c=digest();io_progress("F_WRITE",0,true);
    for(uint64_t i=0;i<cells;){size_t take=cells-i>sizeof b/16?sizeof b/16:(size_t)(cells-i);for(size_t j=0;j<take;++j)put128(b+16*j,F[i+j]);writeall(fd,b,16*take);update(c,b,16*take);i+=take;io_progress("F_WRITE",16*i,false);}finish(c,sha);io_progress("F_FSYNC",fbytes(n),true);syncfd(fd);closefd(fd);if(renameat(rootfd,"txn1.tmp",rootfd,"f.bin"))fail("F publish");syncfd(rootfd);
}
static void checkF(const State *s) { int fd=openfile("f.bin",O_RDONLY);require(length(fd)==fbytes(s->n),"F length");unsigned char h[32];hashfd(fd,h);require(!memcmp(h,s->fsha,32),"F digest");closefd(fd); }
static void results(const State *s,bool create) { char b[4096],c[65],f[65],num[40];hex(cfgsha,c);hex(s->fsha,f);int z=snprintf(b,sizeof b,"# A180215 cfg=%s F=%s\n",c,f);require(z>0,"result header");size_t len=(size_t)z;for(unsigned i=0;i<s->n;++i){decimal(s->ans[i],num);z=snprintf(b+len,sizeof b-len,"%u %s\n",i+1,num);require(z>0&&(size_t)z<sizeof b-len,"result encoding");len+=(size_t)z;}if(create)textfile("res.tsv",b,len);else {int fd=openfile("res.tsv",O_RDONLY);require(length(fd)==len,"result size");char r[4096];readall(fd,r,len);closefd(fd);require(!memcmp(b,r,len),"result mismatch");} }
static void reduce(State *s,int jfd,unsigned char prev[32]) {
    checkF(s);int fd=openfile("f.bin",O_RDONLY);unsigned char left[262144],right[262144];
    while(s->phase==REDUCE){uint64_t limit=UINT64_C(1)<<(s->m-1),U=(UINT64_C(1)<<s->m)-1;size_t take=limit-s->scan>sizeof left/16?sizeof left/16:(size_t)(limit-s->scan);off_t a=(off_t)(16*s->scan),b=(off_t)(16*(U-s->scan-(take-1)));if(lseek(fd,a,SEEK_SET)<0)fail("reduce left");readall(fd,left,16*take);if(lseek(fd,b,SEEK_SET)<0)fail("reduce right");readall(fd,right,16*take);for(size_t i=0;i<take;++i)s->ans[s->m]=add(s->ans[s->m],mul(get128(left+16*i),get128(right+16*(take-1-i))));s->scan+=take;
        if(s->scan==limit){s->ans[s->m]=mul(2,s->ans[s->m]);++s->m;s->scan=0;if(s->m==s->n)s->phase=PRODUCED;}
        if(stopped||now()>=deadline||s->phase==PRODUCED){commit(jfd,s,prev,NULL,0);break;}beat(s,"RUNNING",false);
    }closefd(fd);
}
static int selftest(void) {
    U128 fact=1,visits=1,fall=1;for(unsigned k=1;k<=32;++k)fact=mul(fact,k);require((fact>>117)==1,"32! bit boundary");char b[40];decimal(fact,b);require(!strcmp(b,"263130836933693530167218012160000000"),"32! decimal");for(unsigned k=1;k<=31;++k){fall=mul(fall,32-k);visits=add(visits,fall);}require((visits>>114)==1,"prefix bound115 bits");unsigned char a[16];put128(a,fact);require(get128(a)==fact,"U128 serialization");require(fbytes(32)==(UINT64_C(32)<<30),"F32 bytes");Frame f={0};require(available(&f,32)==UINT32_C(0x7fffffff),"mask31");f.mask=1;f.d=1;require(available(&f,2)==0,"terminal word one");printf("SELFTEST PASS numeric, mask31, terminal prefix, F32 size; no enumeration\n");return 0;
}
int main(int argc,char **argv) {
    started=now();lastbeat=started;require(argc>=2,"usage: init ROOT N | next ROOT SECONDS | status ROOT | audit ROOT | selftest");
    if(!strcmp(argv[1],"selftest")){require(argc==2,"selftest arguments");return selftest();}
    bool init=!strcmp(argv[1],"init"),next=!strcmp(argv[1],"next"),audit=!strcmp(argv[1],"audit"),status=!strcmp(argv[1],"status");require(init||next||audit||status,"unknown command");require(argc==(init||next?4:3),"argument count");unsigned n=0;if(init){n=(unsigned)number(argv[3],32);require(n>=1,"N>=1");}if(next){seconds_limit=(unsigned)number(argv[3],3300);require(seconds_limit>=1,"seconds>=1");}deadline=started+seconds_limit;
    if(init){if(mkdir(argv[2],0700))fail("init requires absent root");}rootopen(argv[2],init||next);n=config(n,init);telemetry_n=n;
    if(init){State s={0};s.n=n;s.depth=1;s.m=1;s.ans[0]=1;unsigned char prev[32]={0};int fd=openfile("walk.bin",O_WRONLY|O_CREAT|O_EXCL);commit(fd,&s,prev,NULL,0);closefd(fd);syncfd(rootfd);syncparent(argv[2]);beat(&s,"INITIALIZED",true);closefd(rootfd);return 0;}
    State s={0};unsigned char prev[32];int fd=openfile("walk.bin",next?O_RDWR:O_RDONLY);uint64_t good=journal(fd,n,&s,prev,NULL),sz=length(fd);bool tail=good!=sz;
    if(!next){if(audit&&s.phase!=WALK){checkF(&s);if(s.phase==PRODUCED)results(&s,false);}printf("{\"N\":%u,\"phase\":%u,\"events\":%" PRIu64 ",\"discardable_EOF_bytes\":%" PRIu64 ",\"independent_validation\":\"NOT_ASSESSED_BY_PRODUCER\"}\n",n,s.phase,s.nodes,sz-good);closefd(fd);closefd(rootfd);return tail?75:0;}
    if(tail){fprintf(stderr,"Discarding incomplete EOF transaction: %" PRIu64 " bytes after audited commit\n",sz-good);if(ftruncate(fd,(off_t)good))fail("truncate tail");syncfd(fd);}discard("txn1.tmp");if(lseek(fd,(off_t)good,SEEK_SET)<0)fail("append seek");++s.seq;beat(&s,"START",true);
    struct sigaction sa={0};sa.sa_handler=handler;if(sigemptyset(&sa.sa_mask)||sigaction(SIGINT,&sa,NULL)||sigaction(SIGTERM,&sa,NULL))fail("signals");
    if(s.phase==WALK){discard("f.bin");uint64_t bytes=fbytes(n);require(bytes<RSS_CAP,"F RSS bound");quota(bytes);U128 *F=calloc((size_t)(bytes/16),16);require(F!=NULL,"F allocation");uint64_t again=journal(fd,n,&s,prev,F);require(again==good,"stable journal");++s.seq;if(lseek(fd,(off_t)good,SEEK_SET)<0)fail("append seek");uint32_t *events=malloc(Q*sizeof *events);require(events!=NULL,"event allocation");unsigned count=0;uint64_t steps=0;
        while(s.depth){Frame *f=&s.stack[s.depth-1];if(f->mode==0){F[f->mask]=add(F[f->mask],1);events[count++]=f->mask;require(s.nodes<UINT64_MAX,"physical event count");++s.nodes;f->rem=available(f,n);f->mode=1;}else if(f->mode==1){if(f->rem){uint32_t bit=f->rem&(~f->rem+1);f->rem^=bit;unsigned v=(unsigned)__builtin_ctz(bit)+1,base=f->a+4*f->b+6*f->c+4*f->d;require(v>=base&&s.depth<32,"child domain");Frame child={f->mask|bit,0,f->b,f->c,f->d,v-base,0};s.stack[s.depth++]=child;}else f->mode=2;}else {--s.depth;memset(&s.stack[s.depth],0,sizeof(Frame));}
            ++steps;if(!s.depth){saveF(F,n,s.fsha);s.phase=n==1?PRODUCED:REDUCE;}
            bool stop=(steps%4096==0)&&(stopped||now()>=deadline);if(count==Q||stop||!s.depth){commit(fd,&s,prev,events,count);count=0;beat(&s,"COMMIT",false);if(stop||!s.depth)break;}
        }free(events);free(F);
    }
    if(s.phase==REDUCE&&!stopped&&now()<deadline)reduce(&s,fd,prev);
    if(s.phase==PRODUCED){checkF(&s);results(&s,true);}beat(&s,s.phase==PRODUCED?"PRODUCED_UNVERIFIED":stopped?"SIGNAL":"BUDGET",true);closefd(fd);closefd(rootfd);return s.phase==PRODUCED?0:75;
}
