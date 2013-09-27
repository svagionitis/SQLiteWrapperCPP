#include <iostream>
#include "gtest/gtest.h"

int main(int argc, char *argv[])
{
    ::testing::GTEST_FLAG(color) = "yes";
    ::testing::GTEST_FLAG(print_time) = false;

    ::testing::InitGoogleTest(&argc, argv);

    return RUN_ALL_TESTS();
}
