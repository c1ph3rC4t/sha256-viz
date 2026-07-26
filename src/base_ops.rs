// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 c1ph3rC4t

/// A trait for types with a [`MutCompU32::compute`] method that returns a [`u32`]
pub trait MutCompU32: std::fmt::Binary + std::fmt::Debug + Clone + PartialEq + Eq {
    /// A [`MutCompU32::compute`] method that should return a [`u32`] and compute all input using the same method recursively.
    fn compute(&mut self) -> u32;
}

impl MutCompU32 for u32 {
    fn compute(&mut self) -> u32 {
        *self
    }
}

/// A u32 with a [`String`] label attached.
#[derive(Clone, PartialEq, Eq)]
pub struct LabeledU32(pub String, pub u32);

impl From<(&str, u32)> for LabeledU32 {
    fn from(val: (&str, u32)) -> Self {
        Self(val.0.to_string(), val.1)
    }
}

impl From<(String, u32)> for LabeledU32 {
    fn from(val: (String, u32)) -> Self {
        Self(val.0, val.1)
    }
}

impl MutCompU32 for LabeledU32 {
    fn compute(&mut self) -> u32 {
        self.1
    }
}

impl std::fmt::Binary for LabeledU32 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:032b}:{}", self.1, self.0)
    }
}

impl std::fmt::Debug for LabeledU32 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Binary::fmt(self, f)
    }
}

/// [`MutCompU32`] implementation of [`u32::wrapping_add`].
#[derive(Clone, PartialEq, Eq)]
pub struct Add232<A: MutCompU32, B: MutCompU32> {
    /// Operands whose [`MutCompU32::compute`] outputs are used as operands for a [`u32::wrapping_add`] addition.
    pub input: (A, B),
    /// The result of a [`u32::wrapping_add`] addition on the [`MutCompU32::compute`] outputs of each operand.
    pub result: u32,
}

impl<A: MutCompU32, B: MutCompU32> Add232<A, B> {
    /// A function for creating a new [`Add232`].
    pub const fn new(a: A, b: B) -> Self {
        Self {
            input: (a, b),
            result: 0,
        }
    }
}

impl<A: MutCompU32, B: MutCompU32> MutCompU32 for Add232<A, B> {
    fn compute(&mut self) -> u32 {
        self.result = self.input.0.compute().wrapping_add(self.input.1.compute());
        self.result
    }
}

impl<A: MutCompU32, B: MutCompU32> std::fmt::Binary for Add232<A, B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let a = format!("{:032b}", self.input.0);
        let b = format!("{:032b}", self.input.1);

        let indent = |s: &str| {
            s.lines()
                .map(|l| format!("  {l}"))
                .collect::<Vec<_>>()
                .join("\n")
        };

        write!(
            f,
            "(
{}
) + (
{}
)
= {:032b}",
            indent(&a),
            indent(&b),
            self.result
        )?;

        Ok(())
    }
}

impl<A: MutCompU32, B: MutCompU32> std::fmt::Debug for Add232<A, B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Binary::fmt(self, f)
    }
}

/// Implementation of the choose function specified by SHA2-256 with exposed internals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ch<A: MutCompU32, B: MutCompU32, C: MutCompU32> {
    /// Operands whose [`MutCompU32::compute`] outputs are used as operands for the choose function specified by SHA2-256.
    pub input: (A, B, C),
    /// The result of a bitwise AND on the [`MutCompU32::compute`] outputs of the first two operands.
    pub ab: u32,
    /// The result of a bitwise AND on the negation of the [`MutCompU32::compute`] output of the first operand and the [`MutCompU32::compute`] output of the last operand.
    pub nac: u32,
    /// The result of a bitwise XOR on the values of `ab` and `nac`. The result is that for every bit `n` if `a[n]` equals `1` then the result equals that of `b[n]` else `c[n]`.
    pub result: u32,
}

impl<A: MutCompU32, B: MutCompU32, C: MutCompU32> Ch<A, B, C> {
    /// A function for creating a new [`Ch`].
    pub const fn new(a: A, b: B, c: C) -> Self {
        Self {
            input: (a, b, c),
            ab: 0,
            nac: 0,
            result: 0,
        }
    }
}

impl<A: MutCompU32, B: MutCompU32, C: MutCompU32> MutCompU32 for Ch<A, B, C> {
    fn compute(&mut self) -> u32 {
        let a = self.input.0.compute();
        let b = self.input.1.compute();
        let c = self.input.2.compute();
        self.ab = a & b;
        self.nac = !a & c;
        self.result = self.ab ^ self.nac;
        self.result
    }
}

impl<A: MutCompU32, B: MutCompU32, C: MutCompU32> std::fmt::Binary for Ch<A, B, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!(
            "e  {:032b}
-----------------------------------
f  {:032b}
g  {:032b}
-----------------------------------
Ch {:032b}",
            self.input.0, self.input.1, self.input.2, self.result
        ))?;

        Ok(())
    }
}

/// Implementation of majority function as specified by SHA2-256 with exposed internals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Maj<A: MutCompU32, B: MutCompU32, C: MutCompU32> {
    /// Operands whose [`MutCompU32::compute`] outputs are used as operands for the majority function specified by SHA2-256.
    pub input: (A, B, C),
    /// The result of a bitwise AND on the [`MutCompU32::compute`] outputs of the first two operands.
    pub ab: u32,
    /// The result of a bitwise AND on the [`MutCompU32::compute`] outputs of the first and last operands.
    pub ac: u32,
    /// The result of a bitwise AND on the [`MutCompU32::compute`] outputs of the last two operands.
    pub bc: u32,
    /// The result of a bitwise XOR on the values of `ab`, `ac` and `bc`. The result is that it picks the state which has majority.
    pub result: u32,
}

impl<A: MutCompU32, B: MutCompU32, C: MutCompU32> Maj<A, B, C> {
    /// A function for creating a new [`Maj`].
    pub const fn new(a: A, b: B, c: C) -> Self {
        Self {
            input: (a, b, c),
            ab: 0,
            ac: 0,
            bc: 0,
            result: 0,
        }
    }
}

impl<A: MutCompU32, B: MutCompU32, C: MutCompU32> MutCompU32 for Maj<A, B, C> {
    fn compute(&mut self) -> u32 {
        let a = self.input.0.compute();
        let b = self.input.1.compute();
        let c = self.input.2.compute();
        self.ab = a & b;
        self.ac = a & c;
        self.bc = b & c;
        self.result = self.ab ^ self.ac ^ self.bc;
        self.result
    }
}

impl<A: MutCompU32, B: MutCompU32, C: MutCompU32> std::fmt::Binary for Maj<A, B, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!(
            "a   {:032b}
b   {:032b}
c   {:032b}
------------------------------------
Maj {:032b}",
            self.input.0, self.input.1, self.input.2, self.result
        ))?;

        Ok(())
    }
}

/// Implementation of σ0 as specified by SHA2-256 with exposed internals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmallSigma0<T: MutCompU32> {
    /// Operand whose [`MutCompU32::compute`] output is used as the operand for σ0 as specified by SHA2-256.
    pub input: T,
    /// The result of performing a rotr7 on the [`MutCompU32::compute`] outputs of the operand.
    pub r7: u32,
    /// The result of performing a rotr18 on the [`MutCompU32::compute`] outputs of the operand.
    pub r18: u32,
    /// The result of performing a shr3 on the [`MutCompU32::compute`] outputs of the operand.
    pub s3: u32,
    /// The result of performing a XOR on the values of `r7`, `r18` and `s3`.
    pub result: u32,
}

impl<T: MutCompU32> SmallSigma0<T> {
    /// A function for creating a new [`SmallSigma0`].
    pub const fn new(input: T) -> Self {
        Self {
            input,
            r7: 0,
            r18: 0,
            s3: 0,
            result: 0,
        }
    }
}

impl<T: MutCompU32> MutCompU32 for SmallSigma0<T> {
    fn compute(&mut self) -> u32 {
        let a = self.input.compute();
        self.r7 = (a >> 7) | (a << 25);
        self.r18 = (a >> 18) | (a << 14);
        self.s3 = a >> 3;
        self.result = self.r7 ^ self.r18 ^ self.s3;
        self.result
    }
}

impl<T: MutCompU32> std::fmt::Binary for SmallSigma0<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!(
            "σ0( {:032b} )
--------------------------------------
r7  {:032b}
r18 {:032b} ^
s3  {:032b} ^
--------------------------------------
  = {:032b}",
            self.input, self.r7, self.r18, self.s3, self.result
        ))?;

        Ok(())
    }
}

/// Implementation of σ1 as specified by SHA2-256 with exposed internals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmallSigma1<T: MutCompU32> {
    /// Operand whose [`MutCompU32::compute`] output is used as the operand for σ1 as specified by SHA2-256.
    pub input: T,
    /// The result of performing a rotr17 on the [`MutCompU32::compute`] outputs of the operand.
    pub r17: u32,
    /// The result of performing a rotr19 on the [`MutCompU32::compute`] outputs of the operand.
    pub r19: u32,
    /// The result of performing a shr10 on the [`MutCompU32::compute`] outputs of the operand.
    pub s10: u32,
    /// The result of performing a XOR on the values of `r17`, `r19` and `s10`.
    pub result: u32,
}

impl<T: MutCompU32> SmallSigma1<T> {
    /// A function for creating a new [`SmallSigma1`].
    pub const fn new(input: T) -> Self {
        Self {
            input,
            r17: 0,
            r19: 0,
            s10: 0,
            result: 0,
        }
    }
}

impl<T: MutCompU32> MutCompU32 for SmallSigma1<T> {
    fn compute(&mut self) -> u32 {
        let a = self.input.compute();
        self.r17 = (a >> 17) | (a << 15);
        self.r19 = (a >> 19) | (a << 13);
        self.s10 = a >> 10;
        self.result = self.r17 ^ self.r19 ^ self.s10;
        self.result
    }
}

impl<T: MutCompU32> std::fmt::Binary for SmallSigma1<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!(
            "σ1( {:032b} )
--------------------------------------
r17 {:032b}
r19 {:032b} ^
s10 {:032b} ^
--------------------------------------
  = {:032b}",
            self.input, self.r17, self.r19, self.s10, self.result
        ))?;

        Ok(())
    }
}

/// Implementation of Σ0 as specified by SHA2-256 with exposed internals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BigSigma0<T: MutCompU32> {
    /// Operand whose [`MutCompU32::compute`] output is used as the operand for Σ0 as specified by SHA2-256.
    pub input: T,
    /// The result of performing a rotr2 on the [`MutCompU32::compute`] outputs of the operand.
    pub r2: u32,
    /// The result of performing a rotr13 on the [`MutCompU32::compute`] outputs of the operand.
    pub r13: u32,
    /// The result of performing a rotr22 on the [`MutCompU32::compute`] outputs of the operand.
    pub r22: u32,
    /// The result of performing a XOR on the values of `r2`, `r13` and `r22`.
    pub result: u32,
}

impl<T: MutCompU32> BigSigma0<T> {
    /// A function for creating a new [`BigSigma0`].
    pub const fn new(input: T) -> Self {
        Self {
            input,
            r2: 0,
            r13: 0,
            r22: 0,
            result: 0,
        }
    }
}

impl<T: MutCompU32> MutCompU32 for BigSigma0<T> {
    fn compute(&mut self) -> u32 {
        let a = self.input.compute();
        self.r2 = (a >> 2) | (a << 30);
        self.r13 = (a >> 13) | (a << 19);
        self.r22 = (a >> 22) | (a << 10);
        self.result = self.r2 ^ self.r13 ^ self.r22;
        self.result
    }
}

impl<T: MutCompU32> std::fmt::Binary for BigSigma0<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!(
            "Σ0( {:032b} )
--------------------------------------
r2  {:032b}
r13 {:032b} ^
r22 {:032b} ^
--------------------------------------
  = {:032b}",
            self.input, self.r2, self.r13, self.r22, self.result
        ))?;

        Ok(())
    }
}

/// Implementation of Σ1 as specified by SHA2-256 with exposed internals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BigSigma1<T: MutCompU32> {
    /// Operand whose [`MutCompU32::compute`] output is used as the operand for Σ1 as specified by SHA2-256.
    pub input: T,
    /// The result of performing a rotr6 on the [`MutCompU32::compute`] outputs of the operand.
    pub r6: u32,
    /// The result of performing a rotr11 on the [`MutCompU32::compute`] outputs of the operand.
    pub r11: u32,
    /// The result of performing a rotr25 on the [`MutCompU32::compute`] outputs of the operand.
    pub r25: u32,
    /// The result of performing a XOR on the values of `r6`, `r11` and `r25`.
    pub result: u32,
}

impl<T: MutCompU32> BigSigma1<T> {
    /// A function for creating a new [`BigSigma1`].
    pub const fn new(input: T) -> Self {
        Self {
            input,
            r6: 0,
            r11: 0,
            r25: 0,
            result: 0,
        }
    }
}

impl<T: MutCompU32> MutCompU32 for BigSigma1<T> {
    fn compute(&mut self) -> u32 {
        let a = self.input.compute();
        self.r6 = (a >> 6) | (a << 26);
        self.r11 = (a >> 11) | (a << 21);
        self.r25 = (a >> 25) | (a << 7);
        self.result = self.r6 ^ self.r11 ^ self.r25;
        self.result
    }
}

impl<T: MutCompU32> std::fmt::Binary for BigSigma1<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!(
            "Σ1( {:032b} )
--------------------------------------
r6  {:032b}
r11 {:032b} ^
r25 {:032b} ^
--------------------------------------
  = {:032b}",
            self.input, self.r6, self.r11, self.r25, self.result
        ))?;

        Ok(())
    }
}
