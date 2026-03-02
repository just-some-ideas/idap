import Foundation
import IDAPAuth

/// Production WebSocket connector backed by URLSession.
final class URLSessionWebSocketConnector: WebSocketConnectable {
    private var task: URLSessionWebSocketTask?
    private let session: URLSession
    private var messageQueue: [String] = []
    private let lock = NSLock()

    /// Called on the URLSession delegate queue when a new message arrives.
    var onMessageReceived: (() -> Void)?

    init(session: URLSession = .shared) {
        self.session = session
    }

    var isConnected: Bool {
        task?.state == .running
    }

    func connect(url: URL, headers: [String: String]) throws {
        var request = URLRequest(url: url)
        for (key, value) in headers {
            request.setValue(value, forHTTPHeaderField: key)
        }
        task = session.webSocketTask(with: request)
        task?.resume()
        receiveNext()
    }

    func send(_ message: String) throws {
        task?.send(.string(message)) { _ in }
    }

    func receive() -> String? {
        lock.lock()
        defer { lock.unlock() }
        return messageQueue.isEmpty ? nil : messageQueue.removeFirst()
    }

    func disconnect() {
        task?.cancel(with: .goingAway, reason: nil)
        task = nil
    }

    private func receiveNext() {
        task?.receive { [weak self] result in
            if case .success(let message) = result {
                if case .string(let text) = message {
                    self?.lock.lock()
                    self?.messageQueue.append(text)
                    self?.lock.unlock()
                    self?.onMessageReceived?()
                }
            }
            if self?.isConnected == true {
                self?.receiveNext()
            }
        }
    }
}
