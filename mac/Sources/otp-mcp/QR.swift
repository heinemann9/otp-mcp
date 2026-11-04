import CoreImage
import Foundation
import ImageIO
import UniformTypeIdentifiers
import Vision

// QR 읽기(Vision)와 시험용 QR 쓰기(CoreImage + ImageIO). 읽은 글자는 시드가 든 주소일 수 있으니 오류 문구에 싣지 않는다(경로만).

/// 이미지 파일의 QR을 모두 읽어 글자로 돌려준다. 하나도 없으면 `OTPError.qrNotFound(path)`.
/// 읽을 수 없는 파일(없음·이미지 아님)은 Vision의 오류가 그대로 올라간다.
func decodeQRCodes(at path: String) throws -> [String] {
    let request = VNDetectBarcodesRequest()
    request.symbologies = [.qr]
    try VNImageRequestHandler(url: URL(fileURLWithPath: path), options: [:]).perform([request])
    let payloads = (request.results ?? []).compactMap(\.payloadStringValue)
    guard !payloads.isEmpty else { throw OTPError.qrNotFound(path) }
    return payloads
}

/// 가져오기 원본 하나에서 OTP 주소(`otpauth://`·`otpauth-migration://`)를 모은다.
/// 이미지(png·jpg·jpeg·heic·tiff)는 QR을 읽고, 그 밖은 글자 파일로 읽어 그 스킴으로 시작하는 줄을 모은다.
/// QR에 다른 글자가 섞여 있어도 OTP 주소가 아닌 것은 버린다. 하나도 없으면 `OTPError.invalidURI`.
/// 없는 파일·이미지나 UTF-8 글자가 아닌 파일은 Vision·Foundation의 영어 문구 대신 경로가 든 한국어 `OTPError`로 바꾼다.
func readOTPURIs(from path: String) throws -> [String] {
    guard FileManager.default.isReadableFile(atPath: path) else { throw OTPError.invalidURI("파일을 읽을 수 없음 (\(path))") }
    let isImage = ["png", "jpg", "jpeg", "heic", "tiff"].contains(URL(fileURLWithPath: path).pathExtension.lowercased())
    let candidates: [String]
    do {
        candidates = isImage
            ? try decodeQRCodes(at: path)
            : try String(contentsOfFile: path, encoding: .utf8).split(whereSeparator: \.isNewline).map(String.init)
    } catch let error as OTPError {
        throw error  // QR 없음
    } catch {
        throw OTPError.unsupported("이미지나 UTF-8 글자 파일이 아님 (\(path))")
    }
    let uris = candidates.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter {
        let text = $0.lowercased()
        return text.hasPrefix("otpauth://") || text.hasPrefix("otpauth-migration://")
    }
    guard !uris.isEmpty else { throw OTPError.invalidURI("otpauth:// 또는 otpauth-migration:// 주소를 찾지 못함 (\(path))") }
    return uris
}

/// 이미지를 PNG 파일로 쓴다.
func writePNG(_ image: CGImage, to url: URL) throws {
    let failure = CocoaError(.fileWriteUnknown, userInfo: [NSFilePathErrorKey: url.path])
    guard let destination = CGImageDestinationCreateWithURL(url as CFURL, UTType.png.identifier as CFString, 1, nil) else { throw failure }
    CGImageDestinationAddImage(destination, image, nil)
    guard CGImageDestinationFinalize(destination) else { throw failure }
}

/// `text`를 QR(모듈 한 칸 = 10픽셀)로 만들어 PNG로 쓴다 — 가져오기 시험용.
func writeQRPNG(_ text: String, to url: URL) throws {
    let filter = CIFilter(name: "CIQRCodeGenerator")!  // 시스템 제공 필터
    filter.setValue(Data(text.utf8), forKey: "inputMessage")
    // 글자가 QR 용량(약 2.9KB)을 넘으면 출력 이미지가 없다.
    guard let code = filter.outputImage?.samplingNearest().transformed(by: CGAffineTransform(scaleX: 10, y: 10)),
          let image = CIContext().createCGImage(code, from: code.extent) else {
        throw CocoaError(.fileWriteUnknown, userInfo: [NSFilePathErrorKey: url.path])
    }
    try writePNG(image, to: url)
}
