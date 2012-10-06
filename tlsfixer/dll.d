/** Helper function for DLL support

This module is based on druntime's $(D core.sys.windows.dll) module.

Copyright: Denis Shelomovskij 2012

License: $(WEB boost.org/LICENSE_1_0.txt, Boost License 1.0).

Authors: Denis Shelomovskij
*/
module tlsfixer.dll;

import core.sys.windows.windows;
import core.sys.windows.threadaux;
import core.stdc.string;
import core.runtime;

import tlsfixer.dlltls;

///////////////////////////////////////////////////////////////////
// support fixing implicit TLS for dynamically loaded DLLs on Windows XP

extern extern (C) __gshared
{
	void* _tlsstart, _tlsend, _tls_callbacks_a;
	int   _tls_index;
}

extern (C) // rt.minfo
{
    void rt_moduleTlsCtor();
    void rt_moduleTlsDtor();
}

// fixup TLS storage, initialize runtime and attach to threads
// to be called from DllMain with reason DLL_PROCESS_ATTACH
bool dll_process_attach( HINSTANCE hInstance, bool attach_threads,
                         void* tlsstart, void* tlsend, void* tls_callbacks_a, int* tlsindex )
{
    if( !setDllTls( hInstance, tlsstart, tlsend, tls_callbacks_a, tlsindex ) )
        return false;

    Runtime.initialize();

    if( !attach_threads )
        return true;

    // attach to all other threads
    return enumProcessThreads(
        function (uint id, void*) {
            if( !thread_findByAddr( id ) )
            {
                // if the OS has not prepared TLS for us, don't attach to the thread
                if( GetTlsDataAddress( id ) )
                {
                    thread_attachByAddr( id );
                    thread_moduleTlsCtor( id );
				}
            }
            return true;
        }, null );
}

// same as above, but only usable if druntime is linked statically
bool dll_process_attach( HINSTANCE hInstance, bool attach_threads = true )
{
    return dll_process_attach( hInstance, attach_threads,
                               &_tlsstart, &_tlsend, &_tls_callbacks_a, &_tls_index );
}

// to be called from DllMain with reason DLL_PROCESS_DETACH
void dll_process_detach( HINSTANCE hInstance, bool detach_threads = true )
{
    // detach from all other threads
    if( detach_threads )
        enumProcessThreads(
            function (uint id, void*) {
                if( id != GetCurrentThreadId() && thread_findByAddr( id ) )
                {
                    thread_moduleTlsDtor( id );
                    thread_detachByAddr( id );
                }
                return true;
            }, null );

    Runtime.terminate();
}

/* Make sure that tlsCtorRun is itself a tls variable
 */
static bool tlsCtorRun;
static this() { tlsCtorRun = true; }
static ~this() { tlsCtorRun = false; }

// to be called from DllMain with reason DLL_THREAD_ATTACH
bool dll_thread_attach( bool attach_thread = true, bool initTls = true )
{
    // if the OS has not prepared TLS for us, don't attach to the thread
//  (happened when running under x64 OS)
    if( !GetTlsDataAddress( GetCurrentThreadId() ) )
        return false;
    if( !thread_findByAddr( GetCurrentThreadId() ) )
    {
        // only attach to thread and initalize it if it is not in the thread list (so it's not created by "new Thread")
        if( attach_thread )
            thread_attachThis();
        if( initTls && !tlsCtorRun ) // avoid duplicate calls
            rt_moduleTlsCtor();
    }
    return true;
}

// to be called from DllMain with reason DLL_THREAD_DETACH
bool dll_thread_detach( bool detach_thread = true, bool exitTls = true )
{
    // if the OS has not prepared TLS for us, we did not attach to the thread
    if( !GetTlsDataAddress( GetCurrentThreadId() ) )
         return false;
    if( thread_findByAddr( GetCurrentThreadId() ) )
    {
        if( exitTls && tlsCtorRun ) // avoid dtors to be run twice
            rt_moduleTlsDtor();
        if( detach_thread )
            thread_detachThis();
    }
    return true;
}
