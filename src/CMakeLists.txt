add_executable(bitmessage
        main.c
        log.c log.h
        protocol.c protocol.h
        inv.c inv.h
        peer.c peer.h
        address.c address.h
        object.c object.c
        utils.c utils.h)
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)