// ios-sdk/Sources/KeyAuthSDK/KeyPromptViewController.swift
#if canImport(UIKit)
import UIKit

/// Built-in UIKit modal prompt for entering, pasting, and verifying a license key.
public final class KeyPromptViewController: UIViewController {
    private let client: LicenseClient
    private let titleText: String
    private let subtitleText: String
    private let prefillKey: String?
    private let initialError: String?
    private let onAuthorized: (LicensePayload) -> Void

    private let cardView = UIView()
    private let titleLabel = UILabel()
    private let subtitleLabel = UILabel()
    private let keyField = UITextField()
    private let errorLabel = UILabel()
    private let submitButton = UIButton(type: .system)
    private let pasteButton = UIButton(type: .system)
    private let spinner = UIActivityIndicatorView(style: .medium)

    public init(
        client: LicenseClient,
        titleText: String,
        subtitleText: String,
        prefillKey: String? = nil,
        initialError: String? = nil,
        onAuthorized: @escaping (LicensePayload) -> Void
    ) {
        self.client = client
        self.titleText = titleText
        self.subtitleText = subtitleText
        self.prefillKey = prefillKey
        self.initialError = initialError
        self.onAuthorized = onAuthorized
        super.init(nibName: nil, bundle: nil)
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) is not supported")
    }

    public override func viewDidLoad() {
        super.viewDidLoad()
        setupUI()
        if let prefillKey, !prefillKey.isEmpty {
            keyField.text = prefillKey
        }
        if let initialError {
            showError(initialError)
        }
    }

    private func setupUI() {
        let blur = UIVisualEffectView(effect: UIBlurEffect(style: .dark))
        blur.frame = view.bounds
        blur.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        view.addSubview(blur)

        cardView.translatesAutoresizingMaskIntoConstraints = false
        cardView.backgroundColor = UIColor(white: 0.12, alpha: 0.96)
        cardView.layer.cornerRadius = 18
        cardView.layer.borderWidth = 1
        cardView.layer.borderColor = UIColor(white: 1.0, alpha: 0.14).cgColor
        view.addSubview(cardView)

        titleLabel.text = titleText
        titleLabel.font = .boldSystemFont(ofSize: 20)
        titleLabel.textColor = .white
        titleLabel.textAlignment = .center

        subtitleLabel.text = subtitleText
        subtitleLabel.font = .systemFont(ofSize: 13)
        subtitleLabel.textColor = UIColor(white: 0.72, alpha: 1)
        subtitleLabel.textAlignment = .center
        subtitleLabel.numberOfLines = 0

        keyField.placeholder = "KTAOV-XXXX-XXXX-XXXX"
        keyField.textColor = .white
        keyField.backgroundColor = UIColor(white: 0.2, alpha: 1)
        keyField.layer.cornerRadius = 10
        keyField.textAlignment = .center
        keyField.autocapitalizationType = .allCharacters
        keyField.autocorrectionType = .no
        keyField.heightAnchor.constraint(equalToConstant: 44).isActive = true

        errorLabel.font = .systemFont(ofSize: 12, weight: .medium)
        errorLabel.textColor = UIColor.systemRed
        errorLabel.textAlignment = .center
        errorLabel.numberOfLines = 0
        errorLabel.isHidden = true

        submitButton.setTitle("Activate", for: .normal)
        submitButton.setTitleColor(.white, for: .normal)
        submitButton.titleLabel?.font = .boldSystemFont(ofSize: 15)
        submitButton.backgroundColor = .systemBlue
        submitButton.layer.cornerRadius = 10
        submitButton.heightAnchor.constraint(equalToConstant: 42).isActive = true
        submitButton.addTarget(self, action: #selector(handleSubmit), for: .touchUpInside)

        pasteButton.setTitle("Paste", for: .normal)
        pasteButton.setTitleColor(.white, for: .normal)
        pasteButton.titleLabel?.font = .systemFont(ofSize: 15, weight: .semibold)
        pasteButton.backgroundColor = UIColor(white: 0.25, alpha: 1)
        pasteButton.layer.cornerRadius = 10
        pasteButton.heightAnchor.constraint(equalToConstant: 42).isActive = true
        pasteButton.addTarget(self, action: #selector(handlePaste), for: .touchUpInside)

        let buttonRow = UIStackView(arrangedSubviews: [submitButton, pasteButton])
        buttonRow.axis = .horizontal
        buttonRow.spacing = 10
        buttonRow.distribution = .fillEqually

        spinner.color = .white
        spinner.hidesWhenStopped = true

        let stack = UIStackView(arrangedSubviews: [titleLabel, subtitleLabel, keyField, errorLabel, buttonRow, spinner])
        stack.axis = .vertical
        stack.spacing = 12
        stack.translatesAutoresizingMaskIntoConstraints = false
        cardView.addSubview(stack)

        NSLayoutConstraint.activate([
            cardView.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            cardView.centerYAnchor.constraint(equalTo: view.centerYAnchor),
            cardView.widthAnchor.constraint(equalToConstant: 320),

            stack.topAnchor.constraint(equalTo: cardView.topAnchor, constant: 22),
            stack.bottomAnchor.constraint(equalTo: cardView.bottomAnchor, constant: -22),
            stack.leadingAnchor.constraint(equalTo: cardView.leadingAnchor, constant: 20),
            stack.trailingAnchor.constraint(equalTo: cardView.trailingAnchor, constant: -20)
        ])
    }

    @objc private func handlePaste() {
        if let text = UIPasteboard.general.string {
            keyField.text = text.trimmingCharacters(in: .whitespacesAndNewlines)
        }
    }

    @objc private func handleSubmit() {
        let key = keyField.text ?? ""
        errorLabel.isHidden = true
        submitButton.isEnabled = false
        spinner.startAnimating()

        client.verify(key: key) { [weak self] result in
            guard let self else { return }
            self.spinner.stopAnimating()
            self.submitButton.isEnabled = true

            switch result {
            case .success(let payload):
                self.dismiss(animated: true) {
                    self.onAuthorized(payload)
                }
            case .failure(let error):
                self.showError(error.localizedDescription)
            }
        }
    }

    private func showError(_ message: String) {
        errorLabel.text = message
        errorLabel.isHidden = false
    }
}
#endif
