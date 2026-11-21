/* Artificial output-only fixture: NOT sequence values; no enumeration. */
#define main checker_entry
#include "state.cpp"
#undef main
int main(int argc,char **argv) {
    try {
        begin_time=clocknow();heartbeat=begin_time;must(argc==2,"synthetic output ROOT");
        rootfd=open(argv[1],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);must(rootfd>=0,"root");
        Check s;s.n=32;s.k=32;s.m=32;s.phase=2;s.cur.clear();
        U128 f=1;for(unsigned i=0;i<32;++i){f=multiply(f,i+1);s.ans[i]=f;expected[i]=f;must(integer(dec(f))==f,"decimal round trip");}
        save(s);publish("val.tsv",validation(s));publish("done.json",completion());
        must(text("val.tsv")==validation(s)&&text("done.json")==completion(),"output audit");
        publish("val.tsv",validation(s));publish("done.json",completion());
        closefile(rootfd);std::cout<<"SYNTHETIC_NOT_SEQUENCE checker output PASS\n";return 0;
    }catch(const std::exception &e){std::cerr<<e.what()<<'\n';return 2;}
}
