/* Artificial output-only fixture: NOT sequence values; no enumeration. */
#define main producer_entry
#include "../src/a180215.c"
#undef main
int main(int argc,char **argv) {
    started=now();lastbeat=started;
    require(argc==2,"synthetic output ROOT");rootopen(argv[1],true);
    State s={0};s.n=32;s.m=32;s.phase=PRODUCED;
    U128 f=1;for(unsigned i=0;i<32;++i){f=mul(f,i+1);s.ans[i]=f;}
    results(&s,true);results(&s,false);results(&s,true);
    closefd(rootfd);puts("SYNTHETIC_NOT_SEQUENCE producer output PASS");return 0;
}
