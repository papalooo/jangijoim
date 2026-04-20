# .devcontainer/Dockerfile
FROM archlinux:base

# 시스템 업데이트 및 필수 개발 도구/보안 패키지 설치
RUN pacman -Syu --noconfirm && \
    pacman -S --noconfirm \
    base-devel \
    python python-pip \
    rustup \
    git \
    nmap \
    tcpdump

# Rust 안정화 버전 초기화
RUN rustup default stable