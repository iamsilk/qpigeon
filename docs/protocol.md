# qpigeon Protocol

## Definitions

$$
\begin{align*}\\

PS &: \text{Public key (for signing)}\\
SS &: \text{Secret key (for signing)}\\
PK &: \text{Public key (for KEM)}\\
SK &: \text{Secret key (for KEM)}\\
K &: \text{Symmetric encryption key}\\
N &: \text{List of used nonces}\\
B &: \text{Contact book}

\end{align*}
$$
$$
\begin{align*}

\text{Sign}_{SS}(M) &= S && \text{Signs message } M \text{ using private key } SS \text{ creating signature } S \text{.}\\
\text{Sign}_{PS}^{-1}(S, M) &= \{0,1\} && \text{Verifies message } M \text{ matches signature } S \text{ using public key } PS \text{.}\\
&&& \text{Outputs 1 when signature matches.}\\
\\
\text{KEM}_{PK}(K) &= C && \text{Encrypts the given key } K \text{ using public key } PK \text{.}\\
\text{KEM}^{-1}_{SK}(C) &= K && \text{Decrypts the given encrypted key } C \text{ using secret key } SK \text{.}\\
&&& \text{KEM stands for Key Encapsulation Mechanism.}\\
\\
\text{Enc}_{K}(M) &= C && \text{Encrypts the given message using symmetric key } K \text{.} \\
\text{Enc}^{-1}_{K}(C) &= M && \text{Decrypts the given ciphertext using symmetric key } K \text{.}\\
\\
\text{Now()} &= T && \text{Outputs the current timestamp.}
\end{align*}
$$

<div style="page-break-after: always;"></div>

## Contact Request and Accept

$$
\text{Bob adds Alice as a contact.}
$$
$$
\begin{align*}

\text{Bob has} &: SS_{\text{Bob}}, PS_{\text{Alice}}, T_{\text{Threshold}}, B, N\\
\text{Server has} &: PS_{\text{Bob}}, PS_{\text{Alice}}, T_{\text{Threshold}}, B, N\\
\text{Alice has} &: SS_{\text{Alice}}, PS_{\text{Bob}}, T_{\text{Threshold}}, B, N\\
\\

\text{Bob calculates} &:\\

T &= \text{Now}()
&& \text{Get current timestamp.}
\\

n &= \{0,1\}^{128} \text{ s.t. } (n, PS_{\text{Bob}}) \notin N
&& \text{Generate nonce.}
\\

N &= N \cup \{(n, PS_{\text{Bob}})\}
&& \text{Add nonce to list.}
\\

S &= \text{Sign}_{SS_{\text{Bob}}}(T||n||PS_{\text{Alice}})
&& \text{Sign contact request.}
\\

B &= B \cup \{(PS_{\text{Alice}}, PS_{\text{Bob}})\}
&& \text{Mark Alice as able to send messages to Bob.}
\\

\\
\text{Bob sends to server} &: S, T, n, PS_{\text{Alice}}
\\
\\

\text{Server calculates} &:\\

S_{\text{Verify}} &= \text{Sign}^{-1}_{PS_{\text{Bob}}}(S, T||n||PS_{\text{Alice}})
&& \text{Verify contact request is from Bob.}
\\

T &\gt \text{Now}() - T_{\text{Threshold}}
&& \text{Verify contact request is recent.}
\\

(n, PS_{\text{Bob}}) & \notin N
&& \text{Verify nonce is new.}
\\

N &= N \cup \{(n, PS_{\text{Bob}})\}
&& \text{Add old nonce to list.}
\\

B &= B \cup \{(PS_{\text{Alice}}, PS_{\text{Bob}})\}
&& \text{Mark Alice as able to send messages to Bob.}
\\

\\
\text{Server sends to Alice} &: S, T, n
\\
\\

\text{Alice calculates} &:\\

S_{\text{Verify}} &= \text{Sign}^{-1}_{PS_{\text{Bob}}}(S, T||n||PS_{\text{Alice}})
&& \text{Verify contact request is from Bob.}\\
&&& \text{If } S_{\text{Verify}} = 0 \text{, reject.}\\

T &\gt \text{Now}() - T_{\text{Threshold}}
&& \text{Verify contact request is recent.}
\\

(n, PS_{\text{Bob}}) & \notin N
&& \text{Verify nonce is new.}
\\

N &= N \cup \{(n, PS_{\text{Bob}})\}
&& \text{Add old nonce to list.}
\\

B &= B \cup \{(PS_{\text{Alice}}, PS_{\text{Bob}})\}
&& \text{Mark Alice as able to send messages to Bob.}
\\

\\

T &= \text{Now}()
&& \text{Get current timestamp.}
\\

n &= \{0,1\}^{128} \text{ s.t. } (n, PS_{\text{Alice}}) \notin N
&& \text{Generate nonce.}
\\

N &= N \cup \{(n, PS_{\text{Alice}})\}
&& \text{Add nonce to list.}
\\

S &= \text{Sign}_{SS_{\text{Alice}}}(T||n||PS_{\text{Bob}})
&& \text{Sign contact request.}
\\

B &= B \cup \{(PS_{\text{Bob}}, PS_{\text{Alice}})\}
&& \text{Mark Bob as able to send messages to Alice.}
\\

\\
\text{Alice sends to server} &: S, T, n, PS_{\text{Bob}}
\\
\\
\end{align*}
$$

$$
\begin{align*}
\text{Server calculates} &:\\

S_{\text{Verify}} &= \text{Sign}^{-1}_{PS_{\text{Alice}}}(S, T||n||PS_{\text{Bob}})
&& \text{Verify contact request is from Alice.}\\
&&& \text{If } S_{\text{Verify}} = 0 \text{, reject.}\\

T &\gt \text{Now}() - T_{\text{Threshold}}
&& \text{Verify contact request is recent.}
\\

(n, PS_{\text{Alice}}) & \notin N
&& \text{Verify nonce is new.}
\\

N &= N \cup \{(n, PS_{\text{Alice}})\}
&& \text{Add old nonce to list.}
\\

B &= B \cup {(PS_{\text{Bob}}, PS_{\text{Alice}})}
&& \text{Mark Bob as able to send messages to Alice.}
\\

\\
\text{Server sends to Bob} &: S, T, n
\\
\\

\text{Bob calculates} &:\\

S_{\text{Verify}} &= \text{Sign}^{-1}_{PS_{\text{Alice}}}(S, T||n||PS_{\text{Bob}})
&& \text{Verify contact request is from Alice.}\\
&&& \text{If } S_{\text{Verify}} = 0 \text{, reject.}\\

T &\gt \text{Now}() - T_{\text{Threshold}}
&& \text{Verify contact request is recent.}
\\

(n, PS_{\text{Alice}}) & \notin N
&& \text{Verify nonce is new.}
\\

N &= N \cup \{(n, PS_{\text{Alice}})\}
&& \text{Add old nonce to list.}
\\

B &= B \cup {(PS_{\text{Bob}}, PS_{\text{Alice}})}
&& \text{Mark Bob as able to send messages to Alice.}
\\
\end{align*}
$$

<div style="page-break-after: always;"></div>

## Public Key (for KEM) Distribution

$$
\text{Alice sends a public key (for KEM) } PK_{\text{Alice}} \text{ to Bob.}
$$
$$
\begin{align*}

\text{Alice has} &: SS_{\text{Alice}}, PK_{\text{Alice}}\\
\text{Server has} &: PS_\text{Alice}\\
\text{Bob has} &: PS_{\text{Alice}}\\
\\

\text{Alice calculates} &:\\

S &= \text{Sign}_{SS_{\text{Alice}}}(PK_{\text{Alice}})
&& \text{Signs public key.}\\

\\
\text{Alice sends to Server} &: S, PK_{\text{Alice}}\\

\\
\text{Server calculates} &:\\

S_{\text{Verify}} &= \text{Sign}^{-1}_{PS_{\text{Alice}}}(S, PK_{\text{Alice}})
&& \text{Verify message is from Alice.}\\
&&& \text{If } S_{\text{Verify}} = 0, \text{reject.}\\

\\
\text{Server sends to Bob} &: S, PK_{\text{Alice}}\\

\\
\text{Bob calculates:}\\

S_{\text{Verify}} &= \text{Sign}^{-1}_{PS_{\text{Alice}}}(S, PK_{\text{Alice}})
&& \text{Verify message is from Alice.}\\
&&& \text{If } S_{\text{Verify}} = 0, \text{reject.}\\

\end{align*}
$$

<div style="page-break-after: always;"></div>

## Bob sends message to Alice

$$
\text{Bob sends a given message } M \text{ to Alice}.
$$
$$
\begin{align*}
\text{Bob has} &: SS_{\text{Bob}}, PK_{\text{Alice}}, N\\
\text{Server has} &: PS_{\text{Bob}}, T_{\text{Threshold}}, B, N\\
\text{Alice has} &: SK_{\text{Alice}}, PS_{\text{Bob}}, T_{\text{Threshold}}, B, N\\
\end{align*}
$$
$$
\begin{align*}
\text{Bob calculates} &:\\

K &= \{0, 1\}^{n}
&& \text{Generates key of length } n \text{.}\\

C_{K} &= \text{KEM}_{PK_{\text{Alice}}}(K)
&& \text{Encrypts key.}\\

C_{M} &= \text{Enc}_{K}(M)
&& \text{Encrypts message.}\\

T &= \text{Now}()
&& \text{Get current timestamp.}
\\

n &= \{0,1\}^{128} \text{ s.t. } (n, PS_{\text{Bob}}) \notin N
&& \text{Generate nonce.}\\

N &= N \cup \{(n, PS_{\text{Bob}})\}
&& \text{Add nonce to list.}\\

S &= \text{Sign}_{SS_{\text{Bob}}}(T||n||C_{K}||C_{M})
&& \text{Sign message.}\\

\\
\text{Bob sends to server} &: S, T, n, C_{K}, C_{M}\\

\\
\text{Server calculates} &:\\
S_{\text{Verify}} &= \text{Sign}^{-1}_{PS_{\text{Bob}}}(S, T||n||C_{K}||C_{M})
&& \text{Verify message is from Bob.}\\
&&& \text{If } S_{\text{Verify}} = 0 \text{, reject.}\\

T &\gt \text{Now}() - T_{\text{Threshold}}
&& \text{Verify message is recent.}
\\

(n, PS_{\text{Bob}}) & \notin N
&& \text{Verify nonce is new.}
\\

N &= N \cup \{(n, PS_{\text{Bob}})\}
&& \text{Add old nonce to list.}
\\

(PS_{\text{Bob}}, PS_{\text{Alice}}) &\in B
&& \text{Verify Bob can message Alice.}
\\

\\
\text{Server sends to Alice} &: S, T,n, C_{K}, C_{M}\\

\\
\text{Alice calculates} &:\\

S_{\text{Verify}} &= \text{Sign}^{-1}_{PS_{\text{Bob}}}(S, T||n||C_{K}||C_{M})
&& \text{Verify message is from Bob.}\\
&&& \text{If } S_{\text{Verify}} = 0 \text{, reject.}\\

T &\gt \text{Now}() - T_{\text{Threshold}}
&& \text{Verify message is recent.}
\\

(n, PS_{\text{Bob}}) & \notin N
&& \text{Verify nonce is new.}
\\

N &= N \cup \{(n, PS_{\text{Bob}})\}
&& \text{Add old nonce to list.}
\\

(PS_{\text{Bob}}, PS_{\text{Alice}}) &\in B
&& \text{Verify Bob can message Alice.}
\\

K &= \text{KEM}^{-1}_{SK_{\text{Alice}}}(C_{K})
&& \text{Decrypt key.}\\
M &= \text{Enc}^{-1}_{K}(C_{M})
&& \text{Decrypt message.}
\end{align*}
$$
