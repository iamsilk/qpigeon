# Exchanges

## Definitions

$$
\begin{align*}\\

PS &: \text{Public key (for signing)}\\
SS &: \text{Secret key (for signing)}\\
PK &: \text{Public key (for KEM)}\\
SK &: \text{Secret key (for KEM)}\\
K &: \text{Symmetric encryption key}

\end{align*}
$$
$$
\begin{align*}

\text{Sign}_{SS}(M) &= S && \text{Signs message } M \text{ using private key } SS \text{ creating signature } S \text{.}\\
\text{Sign}_{PS}^{-1}(M, S) &= \{0,1\} && \text{Verifies message } M \text{ matches signature } S \text{ using public key } PS \text{.}\\
&&& \text{Outputs 1 when signature matches.}\\
\\
\text{KEM}_{PK}(K) &= C && \text{Encrypts the given key } K \text{ using public key } PK \text{.}\\
\text{KEM}^{-1}_{SK}(C) &= K && \text{Decrypts the given encrypted key } C \text{ using secret key } SK \text{.}\\
&&& \text{KEM stands for Key Encapsulation Mechanism.}\\
\\
\text{Enc}_{K}(M) &= C && \text{Encrypts the given message using symmetric key } K \text{.} \\
\text{Enc}^{-1}_{K}(C) &= M && \text{Decrypts the given ciphertext using symmetric key } K \text{.}

\end{align*}
$$

## Bob adds Alice as a contact

$$
\text{Bob adds Alice as a contact.}
$$
$$
\text{Bob has } SS_{\text{Bob}} \text{ and } PS_{\text{Alice}}. \text{Alice has } SS_{\text{Alice}} \text{ and } PS_{\text{Bob}}.
$$
$$
\begin{align*}

\text{Bob calculates} &:\\



\end{align*}
$$

## Alice sends public KEM to Bob

$$
\text{Alice sends a public key (for KEM) } PK_{\text{Alice}} \text{ to Bob.}
$$
$$
\text{Alice has } SS_{\text{Alice}}, PK_{\text{Alice}}. \text{Server has } PS_\text{Alice}. \text{Bob has } PS_{\text{Alice}}.
$$
$$
\begin{align*}

\text{Alice calculates} &:\\

S &= \text{Sign}_{SS_{\text{Alice}}}(PK_{\text{Alice}})
&& \text{Signs public key.}\\

\\
\text{Alice sends to Server} &: S, PK_{\text{Alice}}\\

\\
\text{Server calculates} &:\\

S_{\text{Verify}} &= \text{Sign}^{-1}_{PS_{\text{Alice}}}(PK_{\text{Alice}}, S)
&& \text{Verify message came from Alice.}\\
&&& \text{If } S_{\text{Verify}} = 0, \text{reject.}\\

\\
\text{Server sends to Bob} &: S, PK_{\text{Alice}}\\

\\
\text{Bob calculates:}\\

S_{\text{Verify}} &= \text{Sign}^{-1}_{PS_{\text{Alice}}}(PK_{\text{Alice}}, S)
&& \text{Verify message came from Alice.}\\
&&& \text{If } S_{\text{Verify}} = 0, \text{reject.}\\

\end{align*}
$$

## Bob sends message to Alice

$$
\text{Bob sends a given message } M \text{ to Alice}.
$$
$$
\text{Bob has } SS_{\text{Bob}}, PK_{\text{Alice}}. \text{Server has } PS_{\text{Bob}}. \text{Alice has } SK_{\text{Alice}}, PS_{\text{Bob}}.
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

S &= \text{Sign}_{SS_{\text{Bob}}}(C_{K}||C_{M})
&& \text{Signs encrypted key and message.}\\

\\
\text{Bob sends to server} &: S, C_{K}, C_{M}\\

\\
\text{Server calculates} &:\\
S_{\text{Verify}} &= \text{Sign}^{-1}_{PS_{\text{Bob}}}(C_{K}||C_{M}, S)
&& \text{Verify message came from Bob.}\\
&&& \text{If } S_{\text{Verify}} = 0 \text{, reject.}\\

\\
\text{Server sends to Alice} &: S, C_{K}, C_{M}\\

\\
\text{Alice calculates} &:\\

S_{\text{Verify}} &= \text{Sign}^{-1}_{PS_{\text{Bob}}}(C_{K}||C_{M}, S)
&& \text{Verify message came from Bob.}\\
&&& \text{If } S_{\text{Verify}} = 0 \text{, reject.}\\

K &= \text{KEM}^{-1}_{SK_{\text{Alice}}}(C_{K})
&& \text{Decrypt key.}\\
M &= \text{Enc}^{-1}_{K}(C_{M})
&& \text{Decrypt message.}
\end{align*}
$$

