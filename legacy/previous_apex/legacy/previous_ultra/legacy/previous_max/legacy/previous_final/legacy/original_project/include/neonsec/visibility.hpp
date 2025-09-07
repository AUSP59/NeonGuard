// SPDX-License-Identifier: Apache-2.0
#pragma once
#if defined(_WIN32) || defined(_WIN64)
  #if defined(NEONSEC_CAPI_EXPORTS)
    #define NEONSEC_CAPI __declspec(dllexport)
  #else
    #define NEONSEC_CAPI __declspec(dllimport)
  #endif
#else
  #define NEONSEC_CAPI __attribute__((visibility("default")))
#endif
