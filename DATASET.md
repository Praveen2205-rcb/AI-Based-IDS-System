# Dataset — UNSW-NB15

This project uses the **UNSW-NB15** network intrusion detection dataset published by the University of New South Wales (UNSW Canberra).

The CSV files are **not included in this repository**. Download them from the official source and place them in the `data/` folder before training.

## Required files

| File | Description |
|---|---|
| `UNSW_NB15_training-set.csv` | Training split (175,341 records) |
| `UNSW_NB15_testing-set.csv` | Testing split (82,332 records) |

After download, your folder should look like:

```
data/
├── UNSW_NB15_training-set.csv
└── UNSW_NB15_testing-set.csv
```

## Official download

- **Project page:** https://research.unsw.edu.au/projects/unsw-nb15-dataset
- **Repository:** https://unsworks.unsw.edu.au/items/4dc0e35c-6196-4c9d-945a-c50b981e5955

The dataset includes nine attack categories: Fuzzers, Analysis, Backdoors, DoS, Exploits, Generic, Reconnaissance, Shellcode, and Worms.

## Terms of use

From the original authors (Nour Moustafa and Jill Slay, UNSW):

- **Academic research:** Free use is granted in perpetuity.
- **Commercial use:** Not permitted without prior agreement from the authors.
- **Citation:** Required when using this dataset in any work.

By using this dataset, you agree to these terms. This repository does not grant any additional rights beyond those stated by UNSW.

## Required citations

If you use UNSW-NB15 in a report, thesis, or publication, cite at minimum:

> Moustafa, N., & Slay, J. (2015). UNSW-NB15: a comprehensive data set for network intrusion detection systems (UNSW-NB15 network data set). *2015 Military Communications and Information Systems Conference (MilCIS)*. IEEE.

Additional recommended references:

> Moustafa, N., & Slay, J. (2016). The evaluation of Network Anomaly Detection Systems: Statistical analysis of the UNSW-NB15 dataset and the comparison with the KDD99 dataset. *Information Security Journal: A Global Perspective*, 25(1–3), 1–14.

> Moustafa, N., et al. (2017). Novel geometric area analysis technique for anomaly detection using trapezoidal area estimation on large-scale networks. *IEEE Transactions on Big Data*.

## Contact

For questions about the dataset itself, contact the original author:

- Dr Nour Moustafa — nour.moustafa@unsw.edu.au
