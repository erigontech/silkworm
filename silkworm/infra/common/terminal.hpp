// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <string_view>

namespace silkworm {

// Reset sequence
inline constexpr std::string_view kColorReset = "\x1b[0m";  // Resets fore color to terminal default

// Normal colors
inline constexpr std::string_view kColorBlack = "\x1b[30m";   // Black
inline constexpr std::string_view kColorCoal = "\x1b[90m";    // Black
inline constexpr std::string_view kColorGray = "\x1b[37m";    // White
inline constexpr std::string_view kColorWhite = "\x1b[97m";   // White
inline constexpr std::string_view kColorMaroon = "\x1b[31m";  // Red
inline constexpr std::string_view kColorRed = "\x1b[91m";     // Red
inline constexpr std::string_view kColorGreen = "\x1b[32m";   // Green
inline constexpr std::string_view kColorLime = "\x1b[92m";    // Green
inline constexpr std::string_view kColorOrange = "\x1b[33m";  // Yellow
inline constexpr std::string_view kColorYellow = "\x1b[93m";  // Yellow
inline constexpr std::string_view kColorNavy = "\x1b[34m";    // Blue
inline constexpr std::string_view kColorBlue = "\x1b[94m";    // Blue
inline constexpr std::string_view kColorViolet = "\x1b[35m";  // Purple
inline constexpr std::string_view kColorPurple = "\x1b[95m";  // Purple
inline constexpr std::string_view kColorTeal = "\x1b[36m";    // Cyan
inline constexpr std::string_view kColorCyan = "\x1b[96m";    // Cyan

// Highlight colors
inline constexpr std::string_view kColorBlackHigh = "\x1b[1;30m";   // Black
inline constexpr std::string_view kColorCoalHigh = "\x1b[1;90m";    // Black
inline constexpr std::string_view kColorGrayHigh = "\x1b[1;37m";    // White
inline constexpr std::string_view kColorWhiteHigh = "\x1b[1;97m";   // White
inline constexpr std::string_view kColorMaroonHigh = "\x1b[1;31m";  // Red
inline constexpr std::string_view kColorRedHigh = "\x1b[1;91m";     // Red
inline constexpr std::string_view kColorGreenHigh = "\x1b[1;32m";   // Green
inline constexpr std::string_view kColorLimeHigh = "\x1b[1;92m";    // Green
inline constexpr std::string_view kColorOrangeHigh = "\x1b[1;33m";  // Yellow
inline constexpr std::string_view kColorYellowHigh = "\x1b[1;93m";  // Yellow
inline constexpr std::string_view kColorNavyHigh = "\x1b[1;34m";    // Blue
inline constexpr std::string_view kColorBlueHigh = "\x1b[1;94m";    // Blue
inline constexpr std::string_view kColorVioletHigh = "\x1b[1;35m";  // Purple
inline constexpr std::string_view kColorPurpleHigh = "\x1b[1;95m";  // Purple
inline constexpr std::string_view kColorTealHigh = "\x1b[1;36m";    // Cyan
inline constexpr std::string_view kColorCyanHigh = "\x1b[1;96m";    // Cyan

// Background
inline constexpr std::string_view kBackgroundBlack = "\x1b[40m";    // Black
inline constexpr std::string_view kBackgroundCoal = "\x1b[100m";    // Black
inline constexpr std::string_view kBackgroundGray = "\x1b[47m";     // White
inline constexpr std::string_view kBackgroundWhite = "\x1b[107m";   // White
inline constexpr std::string_view kBackgroundMaroon = "\x1b[41m";   // Red
inline constexpr std::string_view kBackgroundRed = "\x1b[101m";     // Red
inline constexpr std::string_view kBackgroundGreen = "\x1b[42m";    // Green
inline constexpr std::string_view kBackgroundLime = "\x1b[102m";    // Green
inline constexpr std::string_view kBackgroundOrange = "\x1b[43m";   // Yellow
inline constexpr std::string_view kBackgroundYellow = "\x1b[103m";  // Yellow
inline constexpr std::string_view kBackgroundNavy = "\x1b[44m";     // Blue
inline constexpr std::string_view kBackgroundBlue = "\x1b[104m";    // Blue
inline constexpr std::string_view kBackgroundViolet = "\x1b[45m";   // Purple
inline constexpr std::string_view kBackgroundPurple = "\x1b[105m";  // Purple
inline constexpr std::string_view kBackgroundTeal = "\x1b[46m";     // Cyan
inline constexpr std::string_view kBackgroundCyan = "\x1b[106m";    // Cyan

// Underline
inline constexpr std::string_view kColorBlackUnderline = "\x1b[4;30m";   // Black
inline constexpr std::string_view kColorGrayUnderline = "\x1b[4;37m";    // White
inline constexpr std::string_view kColorMaroonUnderline = "\x1b[4;31m";  // Red
inline constexpr std::string_view kColorGreenUnderline = "\x1b[4;32m";   // Green
inline constexpr std::string_view kColorOrangeUnderline = "\x1b[4;33m";  // Yellow
inline constexpr std::string_view kColorNavyUnderline = "\x1b[4;34m";    // Blue
inline constexpr std::string_view kColorVioletUnderline = "\x1b[4;35m";  // Purple
inline constexpr std::string_view kColorTealUnderline = "\x1b[4;36m";    // Cyan

//! \brief Initializes terminal code page to UTF-8 and enables control escape sequences
//! \remarks Is actually needed on Windows only
void init_terminal();

//! Check if specified file descriptor is a teletype (TTY) terminal
bool is_terminal(int fd);

//! Check if standard output is a TTY terminal
bool is_terminal_stdout();

//! Check if standard error is a TTY terminal
bool is_terminal_stderr();

}  // namespace silkworm
