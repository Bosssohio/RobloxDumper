#pragma once
#include "../Core.hpp"
#include "Instance.hpp"
#include <cstdint>
#include <vector>
#include <optional>

struct HumanoidOffsets {
    // --- Core ---
    uint32_t Health = 0;
    uint32_t MaxHealth = 0;
    uint32_t WalkSpeed = 0;
    uint32_t JumpPower = 0;
    uint32_t JumpHeight = 0;

    // --- Booleans ---
    uint32_t AutoJumpEnabled = 0;
    uint32_t AutoRotate = 0;
    uint32_t Sit = 0;
    uint32_t BreakJointsOnDeath = 0;
    uint32_t PlatformStand = 0;
    uint32_t RequiresNeck = 0;
    uint32_t UseJumpPower = 0;

    // --- Floats ---
    uint32_t HipHeight = 0;
    uint32_t MaxSlopeAngle = 0;
    uint32_t WalkTimer = 0;
    uint32_t HealthDisplayDistance = 0; // optional

    // --- Enums/Ints ---
    uint32_t RigType = 0;
    uint32_t HumanoidState = 0;
    uint32_t NameOcclusion = 0; 

    // --- Vector3 (float x3) – we store the offset of the first float ---
    uint32_t CameraOffset = 0;
    uint32_t MoveDirection = 0;

    // --- Object pointers ---
    uint32_t HumanoidRootPart = 0;
    uint32_t SeatPart = 0;

    // --- DisplayName (string) ---
    uint32_t DisplayName = 0;

    bool Valid = false;
};

HumanoidOffsets FindHumanoidOffsets(
    HANDLE hProc,
    uintptr_t dataModelPtr,
    const InstanceOffsets& instanceOffsets
);