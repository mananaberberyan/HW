#include <iostream> 
#include <unistd.h> 
#include <signal.h> 
#include <sys/types.h> 
#include <sys/wait.h> 
#include <sys/user.h> 
#include <pwd.h>
#include <cstring>
#include <ucontext.h>
#include <errno.h>
#include <string.h> 

void sigusr1_handler(int sig, siginfo_t* siginfo, void* context) { 
     pid_t sender_pid = siginfo->si_pid;
     uid_t sender_uid = siginfo->si_uid;     
    std::cout << "Received a SIGUSR1 signal from process " << sender_pid << " executed by " << sender_uid; 
 
 
    struct passwd* passwd_entry = getpwuid(sender_uid); 
    std::string sender_username = passwd_entry->pw_name; 
    std::cout << " (" << sender_username << ")" << std::endl; 
 

    ucontext_t* ucontext = reinterpret_cast<ucontext_t*>(context);  
    std::cout << "State of the context: EIP = " << ucontext->uc_mcontext.gregs[REG_RIP] << ", EAX = " << ucontext->uc_mcontext.gregs[REG_RAX] << ", EBX = " << ucontext->uc_mcontext.gregs[REG_RBX] << std::endl; 
} 

 
int main() { 
    std::cout << "PID: " << getpid() << std::endl;

    struct sigaction action; 
    memset(&action, 0, sizeof(action)); 
    action.sa_sigaction = sigusr1_handler; 
    action.sa_flags = SA_SIGINFO;
    sigemptyset(&action.sa_mask); 
    if (sigaction(SIGUSR1, &action, NULL) < 0) { 
     std::cerr << strerror(errno) << std::endl;
        exit(errno);
    }
    
    while (true) { 
        sleep(10); 
    } 
 
    return 0; 
}
