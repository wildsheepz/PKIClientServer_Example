/*
 * pki_test.h
 *
 *  Created on: Jun 9, 2019
 *      Author: kuanyong
 */

#ifndef APP_ENUMS_H_
#define APP_ENUMS_H_


#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <string.h>
#include <limits.h>

/**
 * Log level definitions
 *
 * If you use the debug_msg() hook for logging, map these into your loggers
 * own log levels.
**/
typedef enum log_e {
    /// No Logging
    LOG_OFF = 0,

    /// Fatal errors that mean the system is left in a broken state
    LOG_FATAL = 100,

    /// Errors that prevent progress, but are not fatal to execution
    LOG_ERROR = 200,

    /// Conditions that may results in errors or undefined behaviour
    LOG_WARN = 300,

    /// Failing to adhere to strict warnings may result in future issues
    LOG_STRICT = 400,

    /// Purely informational
    LOG_INFO = 500,

    /// More detailed information for debug purposes
    LOG_DEBUG = 600,

    /// Highest defined level of detail
    LOG_TRACE = 700,

    /// Don't filter any logs. Only use in WITH_DEBUG.
    LOG_ALL = UINT_MAX
} log_t;


/* %uPKI flags used in upki_status and return flags */
/// %uPKI has been successfully initialised
#define FLAG_INIT      0x00000001

/// %uPKI is unable to send/recv. User should wait for change in status
#define FLAG_WAIT      0x00000002

/// %uPKI is ready to send/recv
#define FLAG_READY     0x00000004

/// An error has occurred. User action may be needed to exit error state.
#define FLAG_ERROR     0x00000008

/// An asynchronous operation has been requested and future event will fire
#define FLAG_ASYNC     0x00000010

/// %uPKI session is successfully established
#define FLAG_SESSOK    0x00000020

/// Sending at this time not possible as overflow and data loss would occur
#define FLAG_TXOVF     0x00000040

/// One or more packets have been received before prior packet consumed
#define FLAG_RXOVF     0x00000080

/// %uPKI service is running
#define FLAG_RUNNING   0x00000100

/// Payload too large
#define PAYLOAD_OSZ    0x00000200

#define ENUM_SZ	4

#ifdef __cplusplus
} //extern "C"
#endif

#endif /* APP_ENUMS_H_ */
