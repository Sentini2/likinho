#pragma once
// Minimal STB Image loader - just enough for PNG loading
// Full version: https://github.com/nothings/stb
// This is a trimmed placeholder. For production, download the full stb_image.h

#ifndef STB_IMAGE_IMPLEMENTATION_GUARD
#define STB_IMAGE_IMPLEMENTATION_GUARD

#include <windows.h>
#include <d3d11.h>
#include <wincodec.h>
#pragma comment(lib, "windowscodecs.lib")

// Load image using Windows Imaging Component (WIC) - no stb_image needed
static bool LoadTextureFromFileWIC(const wchar_t* filename, ID3D11Device* device, 
    ID3D11ShaderResourceView** outSRV, int* outWidth, int* outHeight)
{
    *outSRV = nullptr;
    *outWidth = 0;
    *outHeight = 0;

    CoInitializeEx(nullptr, COINIT_MULTITHREADED);

    IWICImagingFactory* wicFactory = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER,
        IID_PPV_ARGS(&wicFactory));
    if (FAILED(hr)) return false;

    IWICBitmapDecoder* decoder = nullptr;
    hr = wicFactory->CreateDecoderFromFilename(filename, nullptr, GENERIC_READ,
        WICDecodeMetadataCacheOnLoad, &decoder);
    if (FAILED(hr)) { wicFactory->Release(); return false; }

    IWICBitmapFrameDecode* frame = nullptr;
    hr = decoder->GetFrame(0, &frame);
    if (FAILED(hr)) { decoder->Release(); wicFactory->Release(); return false; }

    IWICFormatConverter* converter = nullptr;
    hr = wicFactory->CreateFormatConverter(&converter);
    if (FAILED(hr)) { frame->Release(); decoder->Release(); wicFactory->Release(); return false; }

    hr = converter->Initialize(frame, GUID_WICPixelFormat32bppRGBA, WICBitmapDitherTypeNone,
        nullptr, 0.0, WICBitmapPaletteTypeCustom);
    if (FAILED(hr)) { converter->Release(); frame->Release(); decoder->Release(); wicFactory->Release(); return false; }

    UINT width, height;
    converter->GetSize(&width, &height);

    UINT stride = width * 4;
    UINT bufferSize = stride * height;
    BYTE* buffer = new BYTE[bufferSize];
    hr = converter->CopyPixels(nullptr, stride, bufferSize, buffer);

    if (SUCCEEDED(hr))
    {
        D3D11_TEXTURE2D_DESC desc = {};
        desc.Width = width;
        desc.Height = height;
        desc.MipLevels = 1;
        desc.ArraySize = 1;
        desc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
        desc.SampleDesc.Count = 1;
        desc.Usage = D3D11_USAGE_DEFAULT;
        desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;

        D3D11_SUBRESOURCE_DATA subResource = {};
        subResource.pSysMem = buffer;
        subResource.SysMemPitch = stride;

        ID3D11Texture2D* texture = nullptr;
        hr = device->CreateTexture2D(&desc, &subResource, &texture);
        if (SUCCEEDED(hr))
        {
            D3D11_SHADER_RESOURCE_VIEW_DESC srvDesc = {};
            srvDesc.Format = desc.Format;
            srvDesc.ViewDimension = D3D11_SRV_DIMENSION_TEXTURE2D;
            srvDesc.Texture2D.MipLevels = 1;
            device->CreateShaderResourceView(texture, &srvDesc, outSRV);
            texture->Release();

            *outWidth = (int)width;
            *outHeight = (int)height;
        }
    }

    delete[] buffer;
    converter->Release();
    frame->Release();
    decoder->Release();
    wicFactory->Release();

    return *outSRV != nullptr;
}

#endif // STB_IMAGE_IMPLEMENTATION_GUARD
