#pragma once

namespace ExtraUtilities
{
    struct Vec3
    {
        float x, y, z;
        Vec3() : x(0), y(0), z(0) {}
        Vec3(float x, float y, float z) : x(x), y(y), z(z) {}
        Vec3(double x, double y, double z) : x(static_cast<float>(x)), y(static_cast<float>(y)), z(static_cast<float>(z)) {}
    };
}
