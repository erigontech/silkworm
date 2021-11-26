/*
    Copyright 2021 The Silkworm Authors

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

            http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
*/

#pragma once
#ifndef SILKWORM_COMMON_TERMINAL_HPP_
#define SILKWORM_COMMON_TERMINAL_HPP_

namespace silkworm {

// Reset sequence
inline constexpr const char* kColorReset = "\x1b[0m";    // Resets fore color to terminal default

// Normal colors
inline constexpr const char* kColorBlack = "\x1b[30m";   // Black
inline constexpr const char* kColorCoal = "\x1b[90m";    // Black
inline constexpr const char* kColorGray = "\x1b[37m";    // White
inline constexpr const char* kColorWhite = "\x1b[97m";   // White
inline constexpr const char* kColorMaroon = "\x1b[31m";  // Red
inline constexpr const char* kColorRed = "\x1b[91m";     // Red
inline constexpr const char* kColorGreen = "\x1b[32m";   // Green
inline constexpr const char* kColorLime = "\x1b[92m";    // Green
inline constexpr const char* kColorOrange = "\x1b[33m";  // Yellow
inline constexpr const char* kColorYellow = "\x1b[93m";  // Yellow
inline constexpr const char* kColorNavy = "\x1b[34m";    // Blue
inline constexpr const char* kColorBlue = "\x1b[94m";    // Blue
inline constexpr const char* kColorViolet = "\x1b[35m";  // Purple
inline constexpr const char* kColorPurple = "\x1b[95m";  // Purple
inline constexpr const char* kColorTeal = "\x1b[36m";    // Cyan
inline constexpr const char* kColorCyan = "\x1b[96m";    // Cyan

// Highlight colors
inline constexpr const char* kColorBlackHigh = "\x1b[1;30m";   // Black
inline constexpr const char* kColorCoalHigh = "\x1b[1;90m";    // Black
inline constexpr const char* kColorGrayHigh = "\x1b[1;37m";    // White
inline constexpr const char* kColorWhiteHigh = "\x1b[1;97m";   // White
inline constexpr const char* kColorMaroonHigh = "\x1b[1;31m";  // Red
inline constexpr const char* kColorRedHigh = "\x1b[1;91m";     // Red
inline constexpr const char* kColorGreenHigh = "\x1b[1;32m";   // Green
inline constexpr const char* kColorLimeHigh = "\x1b[1;92m";    // Green
inline constexpr const char* kColorOrangeHigh = "\x1b[1;33m";  // Yellow
inline constexpr const char* kColorYellowHigh = "\x1b[1;93m";  // Yellow
inline constexpr const char* kColorNavyHigh = "\x1b[1;34m";    // Blue
inline constexpr const char* kColorBlueHigh = "\x1b[1;94m";    // Blue
inline constexpr const char* kColorVioletHigh = "\x1b[1;35m";  // Purple
inline constexpr const char* kColorPurpleHigh = "\x1b[1;95m";  // Purple
inline constexpr const char* kColorTealHigh = "\x1b[1;36m";    // Cyan
inline constexpr const char* kColorCyanHigh = "\x1b[1;96m";    // Cyan

// Background
inline constexpr const char* kBackgroundBlack = "\x1b[40m";    // Black
inline constexpr const char* kBackgroundCoal = "\x1b[100m";    // Black
inline constexpr const char* kBackgroundGray = "\x1b[47m";     // White
inline constexpr const char* kBackgroundWhite = "\x1b[107m";   // White
inline constexpr const char* kBackgroundMaroon = "\x1b[41m";   // Red
inline constexpr const char* kBackgroundRed = "\x1b[101m";     // Red
inline constexpr const char* kBackgroundGreen = "\x1b[42m";    // Green
inline constexpr const char* kBackgroundLime = "\x1b[102m";    // Green
inline constexpr const char* kBackgroundOrange = "\x1b[43m";   // Yellow
inline constexpr const char* kBackgroundYellow = "\x1b[103m";  // Yellow
inline constexpr const char* kBackgroundNavy = "\x1b[44m";     // Blue
inline constexpr const char* kBackgroundBlue = "\x1b[104m";    // Blue
inline constexpr const char* kBackgroundViolet = "\x1b[45m";   // Purple
inline constexpr const char* kBackgroundPurple = "\x1b[105m";  // Purple
inline constexpr const char* kBackgroundTeal = "\x1b[46m";     // Cyan
inline constexpr const char* kBackgroundCyan = "\x1b[106m";    // Cyan

// Underline
inline constexpr const char* kColorBlackUnderline = "\x1b[4;30m";   // Black
inline constexpr const char* kColorGrayUnderline = "\x1b[4;37m";    // White
inline constexpr const char* kColorMaroonUnderline = "\x1b[4;31m";  // Red
inline constexpr const char* kColorGreenUnderline = "\x1b[4;32m";   // Green
inline constexpr const char* kColorOrangeUnderline = "\x1b[4;33m";  // Yellow
inline constexpr const char* kColorNavyUnderline = "\x1b[4;34m";    // Blue
inline constexpr const char* kColorVioletUnderline = "\x1b[4;35m";  // Purple
inline constexpr const char* kColorTealUnderline = "\x1b[4;36m";    // Cyan

//! \brief Initializes terminal code page to UTF-8 and enables control escape sequences
//! \remarks Is actually needed on Windows only
void init_terminal();

}  // namespace silkworm

#endif  // SILKWORM_COMMON_TERMINAL_HPP_
