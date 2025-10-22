# Related publications

## Synthetic Network Traffic Generation for Intrusion Detection Systems: a Systematic Literature Review

_Published in ESORICS 2025 International Workshops, 2025_

Authors: Pierre-François Gimenez

Network data can be difficult to collect due to privacy and confidentiality reasons. For these reasons, network datasets are typically created with controlled environments called testbeds. However, these datasets are regularly criticized for their limited size, class imbalance, obsolescence, and lack of actual user activity. Following the rapid development of generative artificial intelligence, new methods have been applied to synthetic network traffic generation without emulation or simulation. This systematic literature review assesses the current state of synthetic network traffic generation for intrusion detection systems.

## TADAM: Learning Timed Automata From Noisy Observations

_Published in SIAM International Conference on Data Mining (SDM25), 2025_

Authors: Lénaïg Cornanguer, Pierre-François Gimenez

Timed Automata (TA) are formal models capable of representing regular languages with timing constraints, making them well-suited for modeling systems where behavior is driven by events occurring over time. Most existing work on TA learning relies on active learning, where access to a teacher is assumed to answer membership queries and provide counterexamples. While this framework offers strong theoretical guarantees, it is impractical for many real-world applications where such a teacher is unavailable. In contrast, passive learning approaches aim to infer TA solely from sequences accepted by the target automaton. However, current methods struggle to handle noise in the data, such as symbol omissions, insertions, or permutations, which often result in excessively large and inaccurate automata. In this paper, we introduce TADAM, a novel approach that leverages the Minimum Description Length (MDL) principle to balance model complexity and data fit, allowing it to distinguish between meaningful patterns and noise. We show that TADAM is significantly more robust to noisy data than existing techniques, less prone to overfitting, and produces concise models that can be manually audited. We further demonstrate its practical utility through experiments on real-world tasks, such as network flow classification and anomaly detection.

## FlowChronicle: Synthetic Network Flow Generation through Pattern Set Mining

_Published in 20th International Conference on emerging Networking EXperiments and Technologies (CoNEXT), 2024_

Authors: Joscha Cüppers, Adrien Schoen, Gregory Blanc, Pierre-Francois Gimenez

Network traffic datasets are regularly criticized, notably for the lack of realism and diversity in their attack or benign traffic. Generating synthetic network traffic using generative machine learning techniques is a recent area of research that could complement experimental test beds and help assess the efficiency of network security tools such as network intrusion detection systems. Most methods generating synthetic network flows disregard the temporal dependencies between them, leading to unrealistic traffic. To address this issue, we introduce FlowChronicle, a novel synthetic network flow generation tool that relies on pattern mining and statistical models to preserve temporal dependencies. We empirically compare our method against state-of-the-art techniques on several criteria, namely realism, diversity, compliance, and novelty. This evaluation demonstrates the capability of FlowChronicle to achieve high-quality generation while significantly outperforming the other methods in preserving temporal dependencies between flows. Besides, in contrast to deep learning methods, the patterns identified by FlowChronicle are explainable, and experts can verify their soundness. Our work substantially advances synthetic network traffic generation, offering a method that enhances both the utility and trustworthiness of the generated network flows.

## A Tale of Two Methods: Unveiling the limitations of GAN and the Rise of Bayesian Networks for Synthetic Network Traffic Generation

_Published in 9th International Workshop on Traffic Measurements for Cybersecurity (WTMC 2024), 2024_

Authors: Adrien Schoen, Gregory Blanc, Pierre-François Gimenez, Yufei Han, Frédéric Majorczyk, Ludovic Me

The evaluation of network intrusion detection systems requires a sufficient amount of mixed network traffic, i.e., composed of both malicious and legitimate flows. In particular, obtaining realistic legitimate traffic is hard. Synthetic network traffic is one of the tools to respond to insufficient or incomplete real-world datasets. In this paper, we only focus on synthetically generating high-quality legitimate traffic and we do not delve into malicious traffic generation. For this specific task, recent contributions make use of advanced machine learning-driven approaches, notably through Generative Adversarial Networks (GANs). However, evaluations of GAN-generated data often disregards pivotal attributes, such as protocol adherence. Our study addresses the gap by proposing a comprehensive set of metrics that assess the quality of synthetic legitimate network traffic. To illustrate the value of these metrics, we empirically compare advanced network-oriented GANs with a simple and yet effective probabilistic generative model, Bayesian Networks (BN). According to our proposed evaluation metrics, BN-based network traffic generation outperforms the state-of-the-art GAN-based opponents. In our study, BN yields substantially more realistic and useful synthetic benign traffic and minimizes the computational costs simultaneously.

# Contributors

## Scientific contributors

- Inria: Pierre-François Gimenez, Yufei Han, Ludovic Mé, Adrien Schoen
- CISPA: Lénaïg Cornanguer, Joscha Cüppers
- Télécom SudParis: Grégory Blanc
- DGA: Frédéric Majorczyk

## Software contributors

- Inria: Pierre-François Gimenez, Adrien Schoen
- CISPA: Lénaïg Cornanguer, Joscha Cüppers
- CentraleSupélec: Dorian Bachelot, Evan Morin, Florentin Labelle

# Contact

You can contact the maintainer at <pierre-francois.gimenez@inria.fr>. Feel free to post an issue on [GitHub](https://github.com/Fos-R/Fos-R/issues).
