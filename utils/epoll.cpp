#include "../include/epolli.hpp"


int epoll_init(){
    int epfd = epoll_create1(0);
    if (epfd < 0) {
        perror("epoll_create1");
        return -1;
    }
    return epfd;

}

int add_pd(int epfd, int fd , uint32_t events){
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = fd;        //register fd
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, tun_fd, &ev) < 0) {
        perror("epoll_ctl");
        return -1;
    }
    return 0;

}

void epoll_watch(int tun_fd,int epfd ) {
    struct epoll_event events[10];
    while (true) {
        int nfds = epoll_wait(epfd, events, 10, -1);
        
        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == tun_fd) {
                //Pass Trigger
            }
        }
    }
    return;
}

void epoll_close(int epfd){
    close(epfd);
    return;
}
