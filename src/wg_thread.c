#define _GNU_SOURCE

#include "wg_thread.h"
#include <switch.h>
#include <errno.h>
#include <time.h>

static int64_t wg_get_thread_limit(void) {
    uint64_t resource_limit_handle = INVALID_HANDLE;
    svcGetInfo(&resource_limit_handle, InfoType_ResourceLimit, INVALID_HANDLE, 0);
    int64_t thread_cur = 0, thread_lim = 0;
    svcGetResourceLimitCurrentValue(&thread_cur, resource_limit_handle, LimitableResource_Threads);
    svcGetResourceLimitLimitValue(&thread_lim, resource_limit_handle, LimitableResource_Threads);
    return thread_lim - thread_cur;
}

static WgThreadAffinityFunc g_wg_affinity_cb = NULL;
static void *g_wg_affinity_cb_user = NULL;

int wg_thread_create(WgThread *thread, WgThreadFunc func, void *arg) {
    if (wg_get_thread_limit() <= 1)
        return -1;
    int r = pthread_create(&thread->thread, NULL, func, arg);
    return r == 0 ? 0 : -1;
}

int wg_thread_join(WgThread *thread, void **retval) {
    int r = pthread_join(thread->thread, retval);
    return r == 0 ? 0 : -1;
}

int wg_thread_set_name(WgThread *thread, const char *name) {
    (void)thread;
    (void)name;
    return 0;
}

void wg_thread_set_affinity(WgThreadName name) {
    // Pin threads to specific cores: WG recv → Core 2
    switch (name) {
        case WG_THREAD_NAME_RECV:
            svcSetThreadCoreMask(-3, 3, 0x4);  // Core 2
            break;
        default:
            break;
    }
    if (g_wg_affinity_cb)
        g_wg_affinity_cb(name, g_wg_affinity_cb_user);
}

void wg_thread_set_affinity_cb(WgThreadAffinityFunc func, void *user) {
    g_wg_affinity_cb = func;
    g_wg_affinity_cb_user = user;
}

int wg_mutex_init(WgMutex *mutex, bool recursive) {
    pthread_mutexattr_t attr;
    int r = pthread_mutexattr_init(&attr);
    if (r != 0)
        return -1;

    pthread_mutexattr_settype(&attr, recursive ? PTHREAD_MUTEX_RECURSIVE : PTHREAD_MUTEX_DEFAULT);
    r = pthread_mutex_init(&mutex->mutex, &attr);
    pthread_mutexattr_destroy(&attr);

    return r == 0 ? 0 : -1;
}

void wg_mutex_fini(WgMutex *mutex) {
    pthread_mutex_destroy(&mutex->mutex);
}

void wg_mutex_lock(WgMutex *mutex) {
    pthread_mutex_lock(&mutex->mutex);
}

int wg_mutex_trylock(WgMutex *mutex) {
    int r = pthread_mutex_trylock(&mutex->mutex);
    if (r == EBUSY)
        return 1;
    return r == 0 ? 0 : -1;
}

void wg_mutex_unlock(WgMutex *mutex) {
    pthread_mutex_unlock(&mutex->mutex);
}

int wg_cond_init(WgCond *cond) {
    pthread_condattr_t attr;
    int r = pthread_condattr_init(&attr);
    if (r != 0)
        return -1;

#ifndef __APPLE__
    r = pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
    if (r != 0) {
        pthread_condattr_destroy(&attr);
        return -1;
    }
#endif

    r = pthread_cond_init(&cond->cond, &attr);
    pthread_condattr_destroy(&attr);

    return r == 0 ? 0 : -1;
}

void wg_cond_fini(WgCond *cond) {
    pthread_cond_destroy(&cond->cond);
}

void wg_cond_wait(WgCond *cond, WgMutex *mutex) {
    pthread_cond_wait(&cond->cond, &mutex->mutex);
}

int wg_cond_timedwait(WgCond *cond, WgMutex *mutex, uint64_t timeout_ms) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    ts.tv_sec += timeout_ms / 1000;
    ts.tv_nsec += (timeout_ms % 1000) * 1000000;
    if (ts.tv_nsec >= 1000000000) {
        ts.tv_sec += ts.tv_nsec / 1000000000;
        ts.tv_nsec %= 1000000000;
    }

    int r = pthread_cond_timedwait(&cond->cond, &mutex->mutex, &ts);
    if (r == ETIMEDOUT)
        return 1;
    return r == 0 ? 0 : -1;
}

void wg_cond_signal(WgCond *cond) {
    pthread_cond_signal(&cond->cond);
}

void wg_cond_broadcast(WgCond *cond) {
    pthread_cond_broadcast(&cond->cond);
}

int wg_stop_cond_init(WgStopCond *cond) {
    cond->pred = false;

    if (wg_mutex_init(&cond->mutex, false) != 0)
        return -1;

    if (wg_cond_init(&cond->cond) != 0) {
        wg_mutex_fini(&cond->mutex);
        return -1;
    }

    return 0;
}

void wg_stop_cond_fini(WgStopCond *cond) {
    wg_cond_fini(&cond->cond);
    wg_mutex_fini(&cond->mutex);
}

void wg_stop_cond_lock(WgStopCond *cond) {
    wg_mutex_lock(&cond->mutex);
}

void wg_stop_cond_unlock(WgStopCond *cond) {
    wg_mutex_unlock(&cond->mutex);
}

int wg_stop_cond_timedwait(WgStopCond *cond, uint64_t timeout_ms) {
    wg_stop_cond_lock(cond);
    while (!cond->pred) {
        int r = wg_cond_timedwait(&cond->cond, &cond->mutex, timeout_ms);
        if (r == 1) {
            wg_stop_cond_unlock(cond);
            return 1;
        }
        if (r != 0) {
            wg_stop_cond_unlock(cond);
            return -1;
        }
    }
    wg_stop_cond_unlock(cond);
    return 0;
}

void wg_stop_cond_signal(WgStopCond *cond) {
    wg_stop_cond_lock(cond);
    cond->pred = true;
    wg_stop_cond_unlock(cond);
    wg_cond_broadcast(&cond->cond);
}

bool wg_stop_cond_check(WgStopCond *cond) {
    wg_stop_cond_lock(cond);
    bool result = cond->pred;
    wg_stop_cond_unlock(cond);
    return result;
}
