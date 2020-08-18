# wilson64

## Description

Wilson64 is a pure ruby x86-64 assembler. No, really. Worst Idea Evar.

Forked from: https://github.com/seattlerb/wilson/
Refactored by [@ollpu](https://github.com/ollpu) to run on modern Ruby, x86-64 (Linux only).

Why "wilson"? I wanted to name it "metal", but there is an existing
project with that name... So I'm naming it after Wilson Bilkovich, who
is about as metal as you can get (and it is easier to spell than
"bilkovich", even tho that sounds more metal).

Why wilson64? I was on a search for the coolest way of submitting code to a local programming contest.
One idea I had was to somehow write assembly in Ruby, assemble and run it -- maybe by calling an external assembler.
External assemblers turned out hard to call without creating files (which the system prohibits).
There were a couple other projects but none of them had what wilson did: it was self-contained in one file.
I need the whole thing to be in one file to submit it to the contest system. So I started trying to get wilson running.
Turns out it only worked on antiquated Ruby and 32-bit platforms. I ended up rewriting most of it in one week of
intense learning of x86 instruction encoding. And hey, I found a [bug](https://stackoverflow.com/questions/52522544/rbp-not-allowed-as-sib-base) in the original code too. The end result is a monstrosity I'm quite proud of.
You can see my submissions to the contest for [2019](https://cses.fi/214/scores/) and [2020](https://cses.fi/314/scores/).
— @ollpu

## Features / Problems

* Generates and runs x86-64 machine code directly. No dependencies.
* Register ruby methods with `defasm`, run inline assembly with `asm`, or make Procs with `asm_proc`.
* Parameters and return values work according to the System V AMD64 calling convention.
* Terrible, yet, awesome.

## Synopsis

```ruby
  class X
    defasm :superfast_meaning_of_life do
      rax.mov 42
    end

    def inline_asm_example
      n = 1000
  
      asm do
        rax.xor rax
        label :count
        rax.inc
        rax.cmp n
        jne :count
      end
    end
  end
  
  p X.new.superfast_meaning_of_life # => 42
  p X.new.inline_asm_example        # => 1000
```

## All features

TODO

## Requirements

x86-64 Linux & Ruby 2.2 or higher.

## Install

Not on rubygems yet.

## License

### The MIT License

Copyright (c) 2008-2009 Ryan Davis, Seattle.rb

Copyright (c) 2018-2019 Roope Salmi

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
'Software'), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
