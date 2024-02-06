#include <iostream>
#include <string>
#include <ctime>

namespace SystemInfo_WIN {
    // Gets a timestamp and seed for the random algorithm below
    unsigned long long TIME = time(0);
    #define XSTR_SEED ((TIME - '0') * 1ull + (TIME - '0') * 10ull + (TIME - '0') * 60ull + (TIME - '0') * 600ull + (TIME - '0') * 3600ull + (TIME - '0') * 36000ull)

    // Not sure how secure this algorithm is
    constexpr unsigned long long linear_congruent_generator(unsigned rounds) {
        unsigned long long sd = 1013904223ull + (1664525ull * ((rounds > 0) ? linear_congruent_generator(rounds - 1) : (XSTR_SEED))) % 0xFFFFFFFF;
        if (rounds == 0 && sd % 2 == 1) {
            return sd + 1;
        }
        return sd;
    };

    // Random algorithm uses ten rounds of the above algorithm
    #define Random() linear_congruent_generator(10)
    #define XSTR_RANDOM_NUMBER(Min, Max) (Min + (Random() % (Max - Min + 1)))

    // Get the ull key
    unsigned long long XORKEY = XSTR_RANDOM_NUMBER(0xF000000, 0xFFFFFFF);

    template<typename Char >
    constexpr Char encrypt_character(const Char character,
        int index) {
        return character ^ (static_cast<Char>(XORKEY) + index);
    }

    template <unsigned size, typename Char>
    class SystemInfo_WIN_Const {
    public:
        const unsigned _nb_chars = (size - 1);
        Char _string[size];

        inline constexpr SystemInfo_WIN_Const(const Char* string)
            : _string{}
        {
            for (unsigned i = 0u; i < size; ++i)
                _string[i] = encrypt_character<Char>(string[i], i);
        }

        const Char* get() const
        {
            Char* string = const_cast<Char*>(_string);
            for (unsigned t = 0; t < _nb_chars; t++) {
                string[t] = string[t] ^ (static_cast<Char>(XORKEY) + t);
            }
            string[_nb_chars] = '\0';
            return string;
        }

    };
}
#define SystemInfo_WIN_d_wchar(my_string) []{ SystemInfo_WIN::SystemInfo_WIN_Const<(sizeof(my_string)/sizeof(wchar_t)), wchar_t> expr(my_string); return expr; }().get()
#define xor_wchar( string ) SystemInfo_WIN_d_wchar( string ) // xors the given wchar string with the generated key
#define SystemInfo_WIN_d(my_string) []{ SystemInfo_WIN::SystemInfo_WIN_Const<(sizeof(my_string)/sizeof(char)), char> expr(my_string); return expr; }().get()
#define xor( string ) SystemInfo_WIN_d( string ) // xors the given string with the generated key