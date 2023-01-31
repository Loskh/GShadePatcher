using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Iced.Intel;
namespace GShadePatcher;
// Copy from https://github.com/goatcorp/Dalamud/blob/master/Dalamud/Game/SigScanner.cs
/// <summary>
/// A SigScanner facilitates searching for memory signatures in a given ProcessModule.
/// </summary>

public class SigScanner : IDisposable {
    public SigScanner(IntPtr module) {

        // Limit the search space to .text section.
        this.SetupSearchSpace(module);
    }

    /// <summary>
    /// Gets a value indicating whether or not the ProcessModule is 32-bit.
    /// </summary>
    public bool Is32BitProcess { get; }

    /// <summary>
    /// Gets the base address of the search area. When copied, this will be the address of the copy.
    /// </summary>
    public IntPtr SearchBase;

    /// <summary>
    /// Gets the base address of the .text section search area.
    /// </summary>
    public IntPtr TextSectionBase => new(this.SearchBase.ToInt64() + this.TextSectionOffset);

    /// <summary>
    /// Gets the offset of the .text section from the base of the module.
    /// </summary>
    public long TextSectionOffset { get; private set; }

    /// <summary>
    /// Gets the size of the text section.
    /// </summary>
    public int TextSectionSize { get; private set; }

    /// <summary>
    /// Gets the base address of the .data section search area.
    /// </summary>
    public IntPtr DataSectionBase => new(this.SearchBase.ToInt64() + this.DataSectionOffset);

    /// <summary>
    /// Gets the offset of the .data section from the base of the module.
    /// </summary>
    public long DataSectionOffset { get; private set; }

    /// <summary>
    /// Gets the size of the .data section.
    /// </summary>
    public int DataSectionSize { get; private set; }

    /// <summary>
    /// Gets the base address of the .rdata section search area.
    /// </summary>
    public IntPtr RDataSectionBase => new(this.SearchBase.ToInt64() + this.RDataSectionOffset);

    /// <summary>
    /// Gets the offset of the .rdata section from the base of the module.
    /// </summary>
    public long RDataSectionOffset { get; private set; }

    /// <summary>
    /// Gets the size of the .rdata section.
    /// </summary>
    public int RDataSectionSize { get; private set; }

    private IntPtr TextSectionTop => this.TextSectionBase + this.TextSectionSize;

    /// <summary>
    /// Scan memory for a signature.
    /// </summary>
    /// <param name="baseAddress">The base address to scan from.</param>
    /// <param name="size">The amount of bytes to scan.</param>
    /// <param name="signature">The signature to search for.</param>
    /// <returns>The found offset.</returns>
    public static IntPtr Scan(IntPtr baseAddress, int size, string signature) {
        var (needle, mask) = ParseSignature(signature);
        var index = IndexOf(baseAddress, size, needle, mask);
        if (index < 0)
            throw new KeyNotFoundException($"Can't find a signature of {signature}");
        return baseAddress + index;
    }

    /// <summary>
    /// Try scanning memory for a signature.
    /// </summary>
    /// <param name="baseAddress">The base address to scan from.</param>
    /// <param name="size">The amount of bytes to scan.</param>
    /// <param name="signature">The signature to search for.</param>
    /// <param name="result">The offset, if found.</param>
    /// <returns>true if the signature was found.</returns>
    public static bool TryScan(IntPtr baseAddress, int size, string signature, out IntPtr result) {
        try {
            result = Scan(baseAddress, size, signature);
            return true;
        }
        catch (KeyNotFoundException) {
            result = IntPtr.Zero;
            return false;
        }
    }

    /// <summary>
    /// Scan for a .data address using a .text function.
    /// This is intended to be used with IDA sigs.
    /// Place your cursor on the line calling a static address, and create and IDA sig.
    /// The signature and offset should not break through instruction boundaries.
    /// </summary>
    /// <param name="signature">The signature of the function using the data.</param>
    /// <param name="offset">The offset from function start of the instruction using the data.</param>
    /// <returns>An IntPtr to the static memory location.</returns>
    public unsafe IntPtr GetStaticAddressFromSig(string signature, int offset = 0) {
        var instructionAddress = (byte*)this.ScanText(signature);
        instructionAddress += offset;

        try {
            var reader = new UnsafeCodeReader(instructionAddress, signature.Length + 8);
            var decoder = Decoder.Create(64, reader, (ulong)instructionAddress, DecoderOptions.AMD);
            while (reader.CanReadByte) {
                var instruction = decoder.Decode();
                if (instruction.IsInvalid) continue;
                if (instruction.Op0Kind is OpKind.Memory || instruction.Op1Kind is OpKind.Memory) {
                    return (IntPtr)instruction.MemoryDisplacement64;
                }
            }
        }
        catch {
            // ignored
        }

        throw new KeyNotFoundException($"Can't find any referenced address in the given signature {signature}.");
    }

    /// <summary>
    /// Try scanning for a .data address using a .text function.
    /// This is intended to be used with IDA sigs.
    /// Place your cursor on the line calling a static address, and create and IDA sig.
    /// </summary>
    /// <param name="signature">The signature of the function using the data.</param>
    /// <param name="result">An IntPtr to the static memory location, if found.</param>
    /// <param name="offset">The offset from function start of the instruction using the data.</param>
    /// <returns>true if the signature was found.</returns>
    public bool TryGetStaticAddressFromSig(string signature, out IntPtr result, int offset = 0) {
        try {
            result = this.GetStaticAddressFromSig(signature, offset);
            return true;
        }
        catch (KeyNotFoundException) {
            result = IntPtr.Zero;
            return false;
        }
    }

    /// <summary>
    /// Scan for a byte signature in the .data section.
    /// </summary>
    /// <param name="signature">The signature.</param>
    /// <returns>The real offset of the found signature.</returns>
    public IntPtr ScanData(string signature) {
        var scanRet = Scan(this.DataSectionBase, this.DataSectionSize, signature);

        return scanRet;
    }

    /// <summary>
    /// Try scanning for a byte signature in the .data section.
    /// </summary>
    /// <param name="signature">The signature.</param>
    /// <param name="result">The real offset of the signature, if found.</param>
    /// <returns>true if the signature was found.</returns>
    public bool TryScanData(string signature, out IntPtr result) {
        try {
            result = this.ScanData(signature);
            return true;
        }
        catch (KeyNotFoundException) {
            result = IntPtr.Zero;
            return false;
        }
    }

    /// <summary>
    /// Scan for a byte signature in the .text section.
    /// </summary>
    /// <param name="signature">The signature.</param>
    /// <returns>The real offset of the found signature.</returns>
    public IntPtr ScanText(string signature) {

        var mBase = this.TextSectionBase;
        var scanRet = Scan(mBase, this.TextSectionSize, signature);

        var insnByte = Marshal.ReadByte(scanRet);

        if (insnByte == 0xE8 || insnByte == 0xE9)
            scanRet = ReadJmpCallSig(scanRet);

        return scanRet;
    }

    /// <summary>
    /// Try scanning for a byte signature in the .text section.
    /// </summary>
    /// <param name="signature">The signature.</param>
    /// <param name="result">The real offset of the signature, if found.</param>
    /// <returns>true if the signature was found.</returns>
    public bool TryScanText(string signature, out IntPtr result) {
        try {
            result = this.ScanText(signature);
            return true;
        }
        catch (KeyNotFoundException) {
            result = IntPtr.Zero;
            return false;
        }
    }

    /// <summary>
    /// Free the memory of the copied module search area on object disposal, if applicable.
    /// </summary>
    public void Dispose() {
        //Marshal.FreeHGlobal(this.moduleCopyPtr);
    }

    /// <summary>
    /// Helper for ScanText to get the correct address for IDA sigs that mark the first JMP or CALL location.
    /// </summary>
    /// <param name="sigLocation">The address the JMP or CALL sig resolved to.</param>
    /// <returns>The real offset of the signature.</returns>
    private static IntPtr ReadJmpCallSig(IntPtr sigLocation) {
        var jumpOffset = Marshal.ReadInt32(sigLocation, 1);
        return IntPtr.Add(sigLocation, 5 + jumpOffset);
    }

    private static (byte[] Needle, bool[] Mask) ParseSignature(string signature) {
        signature = signature.Replace(" ", string.Empty);
        if (signature.Length % 2 != 0)
            throw new ArgumentException("Signature without whitespaces must be divisible by two.", nameof(signature));

        var needleLength = signature.Length / 2;
        var needle = new byte[needleLength];
        var mask = new bool[needleLength];
        for (var i = 0; i < needleLength; i++) {
            var hexString = signature.Substring(i * 2, 2);
            if (hexString == "??" || hexString == "**") {
                needle[i] = 0;
                mask[i] = true;
                continue;
            }

            needle[i] = byte.Parse(hexString, NumberStyles.AllowHexSpecifier);
            mask[i] = false;
        }

        return (needle, mask);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static unsafe int IndexOf(IntPtr bufferPtr, int bufferLength, byte[] needle, bool[] mask) {
        if (needle.Length > bufferLength) return -1;
        var badShift = BuildBadCharTable(needle, mask);
        var last = needle.Length - 1;
        var offset = 0;
        var maxoffset = bufferLength - needle.Length;
        var buffer = (byte*)bufferPtr;

        while (offset <= maxoffset) {
            int position;
            for (position = last; needle[position] == *(buffer + position + offset) || mask[position]; position--) {
                if (position == 0)
                    return offset;
            }

            offset += badShift[*(buffer + offset + last)];
        }

        return -1;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int[] BuildBadCharTable(byte[] needle, bool[] mask) {
        int idx;
        var last = needle.Length - 1;
        var badShift = new int[256];
        for (idx = last; idx > 0 && !mask[idx]; --idx) {
        }

        var diff = last - idx;
        if (diff == 0) diff = 1;

        for (idx = 0; idx <= 255; ++idx)
            badShift[idx] = diff;
        for (idx = last - diff; idx < last; ++idx)
            badShift[needle[idx]] = last - idx;
        return badShift;
    }

    private void SetupSearchSpace(IntPtr module) {
        var baseAddress = module;
        this.SearchBase = baseAddress;
        // We don't want to read all of IMAGE_DOS_HEADER or IMAGE_NT_HEADER stuff so we cheat here.
        var ntNewOffset = Marshal.ReadInt32(baseAddress, 0x3C);
        var ntHeader = baseAddress + ntNewOffset;

        // IMAGE_NT_HEADER
        var fileHeader = ntHeader + 4;
        var numSections = Marshal.ReadInt16(ntHeader, 6);

        // IMAGE_OPTIONAL_HEADER
        var optionalHeader = fileHeader + 20;

        IntPtr sectionHeader;
        if (this.Is32BitProcess) // IMAGE_OPTIONAL_HEADER32
            sectionHeader = optionalHeader + 224;
        else // IMAGE_OPTIONAL_HEADER64
            sectionHeader = optionalHeader + 240;

        // IMAGE_SECTION_HEADER
        var sectionCursor = sectionHeader;
        for (var i = 0; i < numSections; i++) {
            var sectionName = Marshal.ReadInt64(sectionCursor);

            // .text
            switch (sectionName) {
                case 0x747865742E: // .text
                    this.TextSectionOffset = Marshal.ReadInt32(sectionCursor, 12);
                    this.TextSectionSize = Marshal.ReadInt32(sectionCursor, 8);
                    break;
                case 0x617461642E: // .data
                    this.DataSectionOffset = Marshal.ReadInt32(sectionCursor, 12);
                    this.DataSectionSize = Marshal.ReadInt32(sectionCursor, 8);
                    break;
                case 0x61746164722E: // .rdata
                    this.RDataSectionOffset = Marshal.ReadInt32(sectionCursor, 12);
                    this.RDataSectionSize = Marshal.ReadInt32(sectionCursor, 8);
                    break;
            }

            sectionCursor += 40;
        }
    }


    private unsafe class UnsafeCodeReader : CodeReader {
        private readonly int length;
        private readonly byte* address;
        private int pos;

        public UnsafeCodeReader(byte* address, int length) {
            this.length = length;
            this.address = address;
        }

        public bool CanReadByte => this.pos < this.length;

        public override int ReadByte() {
            if (this.pos >= this.length) return -1;
            return *(this.address + this.pos++);
        }
    }
}


