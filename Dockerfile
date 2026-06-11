FROM devkitpro/devkita64:latest

RUN dkp-pacman -Syu --noconfirm && \
    dkp-pacman -S --noconfirm \
    switch-dev \
    switch-sdl2 \
    switch-mesa \
    switch-glfw \
    switch-glad \
    switch-freetype \
    switch-zlib \
    switch-bzip2 \
    dkp-toolchain-vars \
    && dkp-pacman -Scc --noconfirm

WORKDIR /build
