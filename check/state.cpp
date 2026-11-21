/* A180215 separate weighted-state DP coefficient census for Carlo Corti.
 * Shares the proved zero-anchor split and kernel with the C producer.
 * Does not share DFS, pair reduction, frontier layout or journal code.
 * Build: g++-13 -O3 -std=c++17 -Wall -Wextra -Wpedantic -Wshadow
 *        -Wconversion -Wformat=2 -Werror check/state.cpp -o check/state -lcrypto -ldl
 * CLI: next ROOT SECONDS LAYER_GUARD | audit ROOT | selftest.
 * LAYER_GUARD=1..SECONDS is the qualified remaining-time reserve required
 * before another complete DP layer is started; the first layer always starts.
 * Normal guarded stops preserve a completed frontier. Exit75 partial,2 error.
 * Exact coefficients, absent masks included, then full ordered sums.
 * Checkpoint: LE header1024, sorted (LE64 key, LE128 weight) records,
 * SHA256 trailer. Key=(mask<<20)|(a<<15)|(b<<10)|(c<<5)|d; zero is valid.
 * Header magic A215STAT; phase32@8,N32@12,k32@16,m32@20,scan64@24,
 * total states64@32,transitions64@40,peak64@48,records64@56;
 * 32 U128 sums@64; cfg/F/res/checker-source/checker-binary/walk hashes@576.
 * Completed cardinality frontiers are durable; an interrupted current layer
 * is regenerated. Ordered reduction has a committed exact cursor.
 * No dense checker F and no mathematical subprocesses. Linux64 only.
 */
#define _FILE_OFFSET_BITS 64
#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <openssl/evp.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/file.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

__extension__ typedef unsigned __int128 U128;
using Hash=std::array<unsigned char,32>;
constexpr uint64_t DISK=UINT64_C(64)<<30, RAM=UINT64_C(48)<<30;
constexpr size_t HEADER=1024, BUFFER=262144;
static_assert(sizeof(size_t)==8&&sizeof(off_t)==8,"64-bit host required");
struct Rec { U128 w; uint64_t key; };
static_assert(sizeof(Rec)==32,"measured frontier representation");
struct Check {
    unsigned phase=0,n=0,k=0,m=1;
    uint64_t scan=0,states=0,transitions=0,peak=0;
    std::array<U128,32> ans{};
    std::vector<Rec> cur{{1,0}};
};
static int rootfd=-1;
static std::array<Hash,6> binding;
static std::array<U128,32> expected;
static volatile sig_atomic_t interrupted=0;
static double begin_time, stop_time, heartbeat;
static unsigned allowance=0;
static unsigned layer_guard=0;
static unsigned telemetry_n=0;
struct Partial {};
static void must(bool b,const std::string &s) { if(!b)throw std::runtime_error(s); }
static double clocknow() { return std::chrono::duration<double>(std::chrono::steady_clock::now().time_since_epoch()).count(); }
static void signal_stop(int) { interrupted=1; }
static void poll() { if(allowance&&(interrupted||clocknow()>=stop_time))throw Partial(); }
static void io_progress(const char *phase,uint64_t processed) { double t=clocknow();if(t-heartbeat>=5){std::cerr<<"N="<<(telemetry_n?std::to_string(telemetry_n):"UNKNOWN")<<" phase="<<phase<<" processed_units="<<processed<<" durability=UNCOMMITTED_OR_READ_ONLY elapsed="<<t-begin_time<<" invocation_budget="<<allowance<<" ETA=UNKNOWN stop=RUNNING\n";heartbeat=t;} }
static uint64_t num(const std::string &s,uint64_t max) { must(!s.empty(),"empty integer");uint64_t x=0;for(char c:s){must(c>='0'&&c<='9',"unsigned decimal required");unsigned d=static_cast<unsigned>(c-'0');must(d<=max&&x<=(max-d)/10,"integer overflow/domain");x=x*10+d;}return x; }
static U128 add(U128 a,U128 b) { must(a<=~U128(0)-b,"U128 sum overflow");return a+b; }
static U128 multiply(U128 a,U128 b) { must(!a||b<=~U128(0)/a,"U128 product overflow");return a*b; }
static std::string dec(U128 x) { std::string s;do{s.push_back(static_cast<char>('0'+x%10));x/=10;}while(x);std::reverse(s.begin(),s.end());return s; }
static U128 integer(const std::string &s) { must(!s.empty(),"empty U128");must(s=="0"||s.front()!='0',"noncanonical U128");U128 x=0;for(char c:s){must(c>='0'&&c<='9',"U128 decimal grammar");x=add(multiply(x,10),static_cast<unsigned>(c-'0'));}return x; }
static void put(unsigned char *p,uint64_t x,unsigned n) { for(unsigned i=0;i<n;++i){p[i]=static_cast<unsigned char>(x);x>>=8;} }
static uint64_t get(const unsigned char *p,unsigned n) { uint64_t x=0;for(unsigned i=n;i>0;--i)x=x*256+p[i-1];return x; }
static void put128(unsigned char *p,U128 x) { put(p,static_cast<uint64_t>(x),8);put(p+8,static_cast<uint64_t>(x>>64),8); }
static U128 get128(const unsigned char *p) { return U128(get(p,8))+(U128(get(p+8,8))<<64); }
static EVP_MD_CTX *digest() { auto *c=EVP_MD_CTX_new();must(c&&EVP_DigestInit_ex(c,EVP_sha256(),nullptr)==1,"EVP init");return c; }
static void update(EVP_MD_CTX *c,const void *b,size_t n) { must(EVP_DigestUpdate(c,b,n)==1,"EVP update"); }
static Hash finish(EVP_MD_CTX *c) { Hash h{};unsigned k=0;must(EVP_DigestFinal_ex(c,h.data(),&k)==1&&k==32,"EVP final");EVP_MD_CTX_free(c);return h; }
static std::string hex(const Hash &h) { std::string s;constexpr char alphabet[]="0123456789abcdef";for(auto b:h){s.push_back(alphabet[b>>4]);s.push_back(alphabet[b&15]);}return s; }
static void closefile(int fd) { must(close(fd)==0,"close"); }
static void syncfile(int fd) { must(fsync(fd)==0,"fsync"); }
static int openfile(const char *s,int flags) { int fd=openat(rootfd,s,flags|O_CLOEXEC|O_NOFOLLOW,0600);must(fd>=0,std::string("open ")+s);return fd; }
static uint64_t sizefile(int fd) { struct stat s{};must(fstat(fd,&s)==0&&S_ISREG(s.st_mode)&&s.st_nlink==1&&s.st_size>=0,"regular file required");return static_cast<uint64_t>(s.st_size); }
static void readall(int fd,void *vp,size_t n) { auto *p=static_cast<unsigned char*>(vp);while(n){ssize_t k=read(fd,p,n);if(k<0&&errno==EINTR)continue;must(k>0,"short read");p+=k;n-=static_cast<size_t>(k);} }
static void writeall(int fd,const void *vp,size_t n) { const auto *p=static_cast<const unsigned char*>(vp);while(n){ssize_t k=write(fd,p,n);if(k<0&&errno==EINTR)continue;must(k>0,"write");p+=k;n-=static_cast<size_t>(k);} }
static Hash hashfd(int fd) { must(lseek(fd,0,SEEK_SET)==0,"digest seek");std::array<unsigned char,BUFFER>b{};auto *c=digest();uint64_t bytes=0;for(;;){ssize_t k=read(fd,b.data(),b.size());if(k<0&&errno==EINTR)continue;must(k>=0,"hash read");if(!k)break;update(c,b.data(),static_cast<size_t>(k));bytes+=static_cast<uint64_t>(k);io_progress("HASH_READ",bytes);}return finish(c); }
static Hash hashpath(const std::filesystem::path &p) { int fd=open(p.c_str(),O_RDONLY|O_NOFOLLOW|O_CLOEXEC);must(fd>=0,"identity file missing: "+p.string());(void)sizefile(fd);Hash h=hashfd(fd);closefile(fd);return h; }
static Hash hashname(const char *p) { int fd=openfile(p,O_RDONLY);(void)sizefile(fd);auto h=hashfd(fd);closefile(fd);return h; }
static bool exists(const char *p) { struct stat s{};if(fstatat(rootfd,p,&s,AT_SYMLINK_NOFOLLOW)==0)return true;must(errno==ENOENT,"stat error");return false; }
static uint64_t rootbytes() { const std::array<std::string,9> names={"cfg.json","walk.bin","f.bin","check.bin","val.tsv","res.tsv","done.json","txn1.tmp","txn2.tmp"};int fd=openat(rootfd,".",O_RDONLY|O_DIRECTORY|O_CLOEXEC);must(fd>=0,"directory");DIR *d=fdopendir(fd);must(d,"fdopendir");uint64_t bytes=0;errno=0;while(auto *e=readdir(d)){std::string n=e->d_name;if(n=="."||n=="..")continue;must(std::find(names.begin(),names.end(),n)!=names.end(),"unexpected root entry");int f=openfile(n.c_str(),O_RDONLY);uint64_t k=sizefile(f);closefile(f);must(k<=DISK-bytes,"root quota");bytes+=k;errno=0;}must(errno==0,"readdir");must(closedir(d)==0,"closedir");return bytes; }
static void quota(uint64_t n) { must(n<=DISK-rootbytes(),"scratch quota before mutation"); }
static std::string text(const char *p,size_t cap=8192) { int fd=openfile(p,O_RDONLY);uint64_t n=sizefile(fd);must(n<=cap,"text size");std::string b(static_cast<size_t>(n),'\0');readall(fd,b.data(),b.size());closefile(fd);return b; }
static void discard(const char *p) { must(unlinkat(rootfd,p,0)==0||errno==ENOENT,"discard uncommitted transaction");syncfile(rootfd); }
static void publish(const char *p,const std::string &s) { if(exists(p)){must(text(p)==s,"conflicting existing terminal output");return;}quota(s.size());int fd=openfile("txn2.tmp",O_WRONLY|O_CREAT|O_EXCL);writeall(fd,s.data(),s.size());syncfile(fd);closefile(fd);must(renameat(rootfd,"txn2.tmp",rootfd,p)==0,"publish text");syncfile(rootfd); }
static void producer(unsigned n) {
    int fd=openfile("walk.bin",O_RDONLY);uint64_t bytes=sizefile(fd),pos=0,seq=0,nodes=0;Hash prev{};unsigned lastphase=0;std::array<unsigned char,2048> h{};std::array<unsigned char,BUFFER>b{};
    while(pos<bytes){must(bytes-pos>=2080,"incomplete producer journal");readall(fd,h.data(),h.size());must(!memcmp(h.data(),"A215WALK",8),"producer journal magic");uint64_t count=get(h.data()+8,4);unsigned phase=static_cast<unsigned>(get(h.data()+12,4));must(count<=1048576&&phase<=2&&phase>=lastphase&&get(h.data()+16,4)==n&&get(h.data()+24,8)==seq&&get(h.data()+32,8)==nodes+count,"producer journal ordering");must(!memcmp(h.data()+1600,binding[0].data(),32)&&!memcmp(h.data()+1632,prev.data(),32),"producer journal binding");must(count*4+2080<=bytes-pos,"incomplete producer frame");auto *c=digest();update(c,h.data(),h.size());uint64_t remaining=count*4;while(remaining){size_t take=static_cast<size_t>(std::min<uint64_t>(remaining,b.size()));readall(fd,b.data(),take);update(c,b.data(),take);remaining-=take;io_progress("PRODUCER_JOURNAL",pos+2048+count*4-remaining);}Hash got{};readall(fd,got.data(),32);must(finish(c)==got,"producer frame digest");prev=got;pos+=2080+count*4;nodes+=count;++seq;lastphase=phase;}
    must(seq>0&&lastphase==2&&!memcmp(h.data()+1664,binding[1].data(),32),"producer completion/F binding");closefile(fd);binding[5]=hashname("walk.bin");
}
static unsigned inputs() {
    std::string cfg=text("cfg.json"),pre="{\"schema\":1,\"N\":";must(cfg.compare(0,pre.size(),pre)==0,"cfg grammar");size_t end=cfg.find(',',pre.size());must(end!=std::string::npos,"cfg N delimiter");unsigned n=static_cast<unsigned>(num(cfg.substr(pre.size(),end-pre.size()),32));must(n>=1,"cfg N>=1");telemetry_n=n;
    auto exe=std::filesystem::canonical("/proc/self/exe"),src=exe.parent_path().parent_path()/"src";
    Dl_info info{};void *sym=dlsym(RTLD_DEFAULT,"EVP_DigestInit_ex");must(sym&&dladdr(sym,&info)&&info.dli_fname,"crypto location");
    std::string intended="{\"schema\":1,\"N\":"+std::to_string(n)+",\"source\":\""+hex(hashpath(src/"a180215.c"))+"\",\"makefile\":\""+hex(hashpath(src/"Makefile"))+"\",\"binary\":\""+hex(hashpath(src/"a180215"))+"\",\"crypto\":\""+hex(hashpath(std::filesystem::canonical(info.dli_fname)))+"\"}\n";
    must(cfg==intended,"producer config/source/build/binary/dependency mismatch");binding[0]=hashname("cfg.json");
    std::string res=text("res.tsv");std::istringstream in(res);std::string line;must(bool(std::getline(in,line)),"result header");std::string prefix="# A180215 cfg="+hex(binding[0])+" F=";must(line.size()==prefix.size()+64&&line.compare(0,prefix.size(),prefix)==0,"result binding");
    int fd=openfile("f.bin",O_RDONLY);must(sizefile(fd)==(UINT64_C(16)<<(n-1)),"F length");binding[1]=hashfd(fd);closefile(fd);must(line.substr(prefix.size())==hex(binding[1]),"F digest mismatch");
    std::string canonical=line+'\n';for(unsigned i=0;i<n;++i){must(bool(std::getline(in,line)),"missing result row");auto pos=line.find(' ');must(pos!=std::string::npos&&line.substr(0,pos)==std::to_string(i+1),"result index");expected[i]=integer(line.substr(pos+1));canonical+=std::to_string(i+1)+" "+dec(expected[i])+"\n";}must(!std::getline(in,line)&&res==canonical,"result grammar/trailing bytes");
    binding[2]=hashname("res.tsv");binding[3]=hashpath(exe.parent_path()/"state.cpp");binding[4]=hashpath(exe);producer(n);return n;
}
static uint64_t key(uint32_t mask,unsigned a,unsigned b,unsigned c,unsigned d) { must(a<32&&b<32&&c<32&&d<32,"coordinate packing");return(uint64_t(mask)<<20)|(uint64_t(a)<<15)|(uint64_t(b)<<10)|(uint64_t(c)<<5)|d; }
static uint32_t maskof(uint64_t k) { return static_cast<uint32_t>(k>>20); }
static void verifyrec(const Rec &r,unsigned n,unsigned k) { uint32_t mask=maskof(r.key);must(r.key<(UINT64_C(1)<<51)&&mask<(UINT64_C(1)<<(n-1))&&static_cast<unsigned>(__builtin_popcount(mask))==k&&r.w>0,"frontier key/weight");unsigned a=static_cast<unsigned>((r.key>>15)&31),b=static_cast<unsigned>((r.key>>10)&31),c=static_cast<unsigned>((r.key>>5)&31),d=static_cast<unsigned>(r.key&31);must(4*a+6*b+4*c+d<n,"terminal coordinate bound");unsigned sum=0;for(unsigned i=0;i<n-1;++i)if(mask&(UINT32_C(1)<<i))sum+=i+1;unsigned boundary=15*a+11*b+5*c+d;must(sum>=boundary&&(sum-boundary)%16==0,"weighted boundary invariant");U128 fact=1;for(unsigned i=1;i<=k;++i)fact=multiply(fact,i);must(r.w<=fact,"state factorial bound"); }
static std::array<unsigned char,HEADER> header(const Check &s) { std::array<unsigned char,HEADER> h{};memcpy(h.data(),"A215STAT",8);put(h.data()+8,s.phase,4);put(h.data()+12,s.n,4);put(h.data()+16,s.k,4);put(h.data()+20,s.m,4);put(h.data()+24,s.scan,8);put(h.data()+32,s.states,8);put(h.data()+40,s.transitions,8);put(h.data()+48,s.peak,8);put(h.data()+56,s.cur.size(),8);for(unsigned i=0;i<32;++i)put128(h.data()+64+16*i,s.ans[i]);for(unsigned i=0;i<6;++i)memcpy(h.data()+576+32*i,binding[i].data(),32);return h; }
static void save(const Check &s) { must(s.cur.size()<=(DISK-HEADER-32)/24,"checkpoint length overflow");uint64_t bytes=HEADER+24*uint64_t(s.cur.size())+32;quota(bytes);int fd=openfile("txn2.tmp",O_WRONLY|O_CREAT|O_EXCL);auto h=header(s);auto *c=digest();writeall(fd,h.data(),h.size());update(c,h.data(),h.size());std::array<unsigned char,BUFFER/24*24>b{};size_t i=0;while(i<s.cur.size()){size_t take=std::min(b.size()/24,s.cur.size()-i);for(size_t j=0;j<take;++j){put(b.data()+24*j,s.cur[i+j].key,8);put128(b.data()+24*j+8,s.cur[i+j].w);}writeall(fd,b.data(),24*take);update(c,b.data(),24*take);i+=take;io_progress("CHECKPOINT_WRITE",i);}auto sha=finish(c);writeall(fd,sha.data(),sha.size());syncfile(fd);closefile(fd);must(renameat(rootfd,"txn2.tmp",rootfd,"check.bin")==0,"checkpoint rename");syncfile(rootfd); }
static Check load(unsigned n) { Check s;s.n=n;s.ans[0]=1;if(!exists("check.bin")){must(!exists("done.json")&&!exists("val.tsv"),"missing checkpoint with terminal artifacts");return s;}int fd=openfile("check.bin",O_RDONLY);uint64_t bytes=sizefile(fd);must(bytes>=HEADER+32&&bytes<=DISK,"checkpoint size");std::array<unsigned char,HEADER>h{};readall(fd,h.data(),h.size());must(!memcmp(h.data(),"A215STAT",8),"checkpoint magic");s.phase=static_cast<unsigned>(get(h.data()+8,4));must(get(h.data()+12,4)==n,"checkpoint N");s.k=static_cast<unsigned>(get(h.data()+16,4));s.m=static_cast<unsigned>(get(h.data()+20,4));s.scan=get(h.data()+24,8);s.states=get(h.data()+32,8);s.transitions=get(h.data()+40,8);s.peak=get(h.data()+48,8);uint64_t count=get(h.data()+56,8);must(count<=(bytes-HEADER-32)/24&&HEADER+24*count+32==bytes,"checkpoint record count");must(count<=(RAM-(UINT64_C(128)<<20))/sizeof(Rec),"checkpoint memory quota");must(s.phase<=2&&s.k<=n&&s.m>=1&&s.m<=n,"checkpoint phase/cursor");if(s.phase==1)must(s.m<n&&s.scan<(UINT64_C(1)<<s.m),"ordered cursor");if(s.phase>0)must(count==0&&s.k==n,"closed frontier");for(unsigned i=0;i<32;++i)s.ans[i]=get128(h.data()+64+16*i);s.cur.clear();s.cur.reserve(static_cast<size_t>(count));auto *c=digest();update(c,h.data(),h.size());std::array<unsigned char,24>b{};for(uint64_t i=0;i<count;++i){readall(fd,b.data(),24);update(c,b.data(),24);Rec r{get128(b.data()+8),get(b.data(),8)};verifyrec(r,n,s.k);must(s.cur.empty()||s.cur.back().key<r.key,"frontier sorting/duplicates");s.cur.push_back(r);if(i%65536==0)io_progress("CHECKPOINT_LOAD",i);}Hash got{};readall(fd,got.data(),32);must(finish(c)==got,"checkpoint digest");closefile(fd);must(header(s)==h,"checkpoint identity/canonical header");return s; }
static void beat(const Check &s,const char *why,bool force=false) { double t=clocknow();if(force||t-heartbeat>=5){struct rusage r{};must(getrusage(RUSAGE_SELF,&r)==0,"rusage");std::cerr<<"N="<<s.n<<" phase="<<(s.phase==0?"COEFFICIENTS":s.phase==1?"ORDERED":"VALIDATED")<<" next_layer="<<s.k<<" states="<<s.states<<" frontier="<<s.cur.size()<<" m="<<s.m<<" scan="<<s.scan<<" elapsed="<<t-begin_time<<" invocation_budget="<<allowance<<" layer_guard="<<layer_guard<<" peak_RSS_bytes="<<uint64_t(r.ru_maxrss)*1024<<" root_bytes="<<rootbytes()<<" ETA=UNKNOWN stop="<<why<<'\n';heartbeat=t;} }
static void coefficients(const Check &s) {
    int fd=openfile("f.bin",O_RDONLY);std::array<unsigned char,BUFFER>b{};uint64_t cells=UINT64_C(1)<<(s.n-1),i=0;size_t pos=0;
    while(i<cells){size_t take=static_cast<size_t>(std::min<uint64_t>(b.size()/16,cells-i));readall(fd,b.data(),16*take);for(size_t j=0;j<take;++j){uint64_t mask=i+j;if(static_cast<unsigned>(__builtin_popcountll(mask))!=s.k)continue;U128 sum=0;while(pos<s.cur.size()&&maskof(s.cur[pos].key)==mask){sum=add(sum,s.cur[pos++].w);}must(get128(b.data()+16*j)==sum,"F coefficient mismatch mask="+std::to_string(mask));}i+=take;try{poll();}catch(...){closefile(fd);throw;}beat(s,"SCANNING");}
    closefile(fd);must(pos==s.cur.size(),"uncompared frontier mask");
}
class Flat {
    static constexpr uint64_t empty=UINT64_MAX;
    std::vector<uint64_t> keys;
    std::vector<U128> weights;
    size_t used=0;
    uint64_t current_bytes;
    static uint64_t mix(uint64_t x) { x^=x>>30;x*=UINT64_C(0xbf58476d1ce4e5b9);x^=x>>27;x*=UINT64_C(0x94d049bb133111eb);return x^(x>>31); }
    void grow() { size_t next=keys.empty()?16:keys.size()*2;must(next>keys.size()&&uint64_t(next)<=RAM/24,"hash growth overflow");must(current_bytes+24*uint64_t(keys.size())+24*uint64_t(next)+(UINT64_C(128)<<20)<=RAM,"simultaneous hash growth RSS quota");std::vector<uint64_t> nk(next,empty);std::vector<U128> nw(next,0);for(size_t i=0;i<keys.size();++i){if(keys[i]!=empty){size_t p=static_cast<size_t>(mix(keys[i]))&(next-1);while(nk[p]!=empty)p=(p+1)&(next-1);nk[p]=keys[i];nw[p]=weights[i];}if(i%65536==0){poll();io_progress("HASH_GROW",i);}}keys.swap(nk);weights.swap(nw); }
public:
    explicit Flat(uint64_t current):current_bytes(current) {}
    void insert(uint64_t k,U128 w) { if(keys.empty()||used>=keys.size()*7/10)grow();size_t p=static_cast<size_t>(mix(k))&(keys.size()-1);while(keys[p]!=empty&&keys[p]!=k)p=(p+1)&(keys.size()-1);if(keys[p]==empty){keys[p]=k;++used;}weights[p]=add(weights[p],w); }
    std::vector<Rec> sorted() { must(24*uint64_t(keys.size())+sizeof(Rec)*uint64_t(used)+(UINT64_C(128)<<20)<=RAM,"hash/flatten overlap RSS quota");std::vector<Rec> out;out.reserve(used);for(size_t i=0;i<keys.size();++i){if(keys[i]!=empty)out.push_back({weights[i],keys[i]});if(i%65536==0){poll();io_progress("HASH_FLATTEN",i);}}uint64_t comparisons=0;std::sort(out.begin(),out.end(),[&comparisons](const Rec &a,const Rec &b){if(++comparisons%1048576==0){poll();io_progress("FRONTIER_SORT",comparisons);}return a.key<b.key;});return out; }
};
static std::vector<Rec> advance(Check &s) { Flat hash(s.cur.capacity()*sizeof(Rec));uint32_t all=(UINT32_C(1)<<(s.n-1))-1;size_t i=0;uint64_t transitions=0;for(const Rec &r:s.cur){unsigned a=static_cast<unsigned>((r.key>>15)&31),b=static_cast<unsigned>((r.key>>10)&31),c=static_cast<unsigned>((r.key>>5)&31),d=static_cast<unsigned>(r.key&31),base=a+4*b+6*c+4*d;for(unsigned v=base>1?base:1;v<s.n;++v){uint32_t bit=UINT32_C(1)<<(v-1);if(!(maskof(r.key)&bit)){hash.insert(key((maskof(r.key)|bit)&all,b,c,d,v-base),r.w);must(transitions<UINT64_MAX,"transition counter");++transitions;}}if(++i%4096==0){poll();beat(s,"BUILDING");}}must(s.states<=UINT64_MAX-s.cur.size()&&s.transitions<=UINT64_MAX-transitions,"work counters");s.states+=s.cur.size();s.transitions+=transitions;s.peak=std::max(s.peak,uint64_t(s.cur.size()));std::vector<Rec>().swap(s.cur);return hash.sorted(); }
static void ordered(Check &s) { int fd=openfile("f.bin",O_RDONLY);std::array<unsigned char,BUFFER> a{},b{};while(s.phase==1){uint64_t limit=UINT64_C(1)<<s.m,U=limit-1;size_t take=static_cast<size_t>(std::min<uint64_t>(a.size()/16,limit-s.scan));must(lseek(fd,static_cast<off_t>(16*s.scan),SEEK_SET)>=0,"ordered left seek");readall(fd,a.data(),16*take);must(lseek(fd,static_cast<off_t>(16*(U-s.scan-take+1)),SEEK_SET)>=0,"ordered right seek");readall(fd,b.data(),16*take);for(size_t i=0;i<take;++i)s.ans[s.m]=add(s.ans[s.m],multiply(get128(a.data()+16*i),get128(b.data()+16*(take-i-1))));s.scan+=take;if(s.scan==limit){must(s.ans[s.m]==expected[s.m],"ordered count differs from producer");++s.m;s.scan=0;if(s.m==s.n)s.phase=2;}if(interrupted||clocknow()>=stop_time||s.phase==2){save(s);break;}beat(s,"REDUCING");}closefile(fd); }
static std::string validation(const Check &s) { std::string v="# A180215 exact coefficients including zero; full ordered reduction\n# cfg="+hex(binding[0])+" F="+hex(binding[1])+" checker_source="+hex(binding[3])+" checker_binary="+hex(binding[4])+"\n";for(unsigned i=0;i<s.n;++i){must(s.ans[i]==expected[i],"terminal answer conflict");v+=std::to_string(i+1)+"\t"+dec(s.ans[i])+"\tPASS\n";}return v; }
static std::string completion() { return "{\"schema\":1,\"status\":\"VALIDATED\",\"cfg\":\""+hex(binding[0])+"\",\"F\":\""+hex(binding[1])+"\",\"res\":\""+hex(binding[2])+"\",\"walk\":\""+hex(binding[5])+"\",\"check\":\""+hex(hashname("check.bin"))+"\",\"val\":\""+hex(hashname("val.tsv"))+"\"}\n"; }
static int selftest() { U128 f=1;for(unsigned i=1;i<=32;++i)f=multiply(f,i);must(dec(f)=="263130836933693530167218012160000000","factorial decimal");std::array<unsigned char,16>b{};put128(b.data(),f);must(get128(b.data())==f,"LE128");must(key(UINT32_C(0x7fffffff),31,31,31,31)==(UINT64_C(1)<<51)-1,"packing51");Flat h(0);h.insert(0,1);h.insert(0,2);h.insert(key(1,0,0,0,1),1);auto v=h.sorted();must(v.size()==2&&v[0].key==0&&v[0].w==3,"zero key and multiplicities");std::cout<<"SELFTEST PASS packed51, zero key, U128, exact multiplicity\n";return 0; }
int main(int argc,char **argv) {
    try { begin_time=clocknow();heartbeat=begin_time;must(argc>=2,"usage next ROOT SECONDS LAYER_GUARD | audit ROOT | selftest");std::string mode=argv[1];if(mode=="selftest"){must(argc==2,"selftest args");return selftest();}bool run=mode=="next";must(run||mode=="audit","unknown mode");must(argc==(run?5:3),"argument count");if(run){allowance=static_cast<unsigned>(num(argv[3],3300));must(allowance>=1,"seconds>=1");layer_guard=static_cast<unsigned>(num(argv[4],allowance));must(layer_guard>=1,"layer_guard>=1 and <=seconds");}stop_time=begin_time+allowance;rootfd=open(argv[2],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);must(rootfd>=0,"root open");must(flock(rootfd,(run?LOCK_EX:LOCK_SH)|LOCK_NB)==0,"root busy");(void)rootbytes();unsigned n=inputs();Check s=load(n);
        if(!run){must(s.phase==2,"not fully validated");must(text("val.tsv")==validation(s)&&text("done.json")==completion(),"terminal audit conflict");beat(s,"AUDIT_PASS",true);closefile(rootfd);return 0;}
        discard("txn2.tmp");if(!exists("check.bin"))save(s);struct sigaction sa{};sa.sa_handler=signal_stop;must(sigemptyset(&sa.sa_mask)==0&&sigaction(SIGINT,&sa,nullptr)==0&&sigaction(SIGTERM,&sa,nullptr)==0,"signal handlers");beat(s,"START",true);
        unsigned durable_k=s.k;uint64_t durable_states=s.states;
        try { while(s.phase==0){coefficients(s);s.cur=advance(s);++s.k;if(s.k==s.n){must(s.cur.empty(),"frontier after all labels");s.phase=s.n==1?2:1;}save(s);durable_k=s.k;durable_states=s.states;beat(s,"LAYER_COMMITTED",s.phase!=0);if(s.phase==0&&stop_time-clocknow()<layer_guard){beat(s,"FRONTIER_GUARD",true);closefile(rootfd);return 75;}poll();}if(s.phase==1)ordered(s); }catch(const Partial&){std::cerr<<"N="<<n<<" phase=PARTIAL_INVOCATION committed_layer_cursor="<<durable_k<<" committed_states="<<durable_states<<" durable_checkpoint=check.bin elapsed="<<clocknow()-begin_time<<" invocation_budget="<<allowance<<" layer_guard="<<layer_guard<<" stop=SIGNAL_OR_BUDGET\n";closefile(rootfd);return 75;}
        if(s.phase==2){publish("val.tsv",validation(s));publish("done.json",completion());}beat(s,s.phase==2?"VALIDATED":"BUDGET",true);closefile(rootfd);return s.phase==2?0:75;
    }catch(const std::exception &e){std::cerr<<"ERROR: "<<e.what()<<" errno="<<errno<<'\n';if(rootfd>=0)(void)close(rootfd);return 2;}
}
