#pragma once

#include "bzr.h"

namespace MapSelectionFix
{
    class LuaInterop
    {
    public:
        static void Initialize();
        static void Shutdown();

        static bool HasState();
        static bool PushVectorCompat(const BZR::VECTOR_3D& v);
        static bool PushMatrixCompat(const BZR::MAT_3D& m);
    };
}
