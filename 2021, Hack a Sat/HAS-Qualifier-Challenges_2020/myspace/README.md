# Quals Challenge: My 0x20 #

**Category:** Astronomy, Astrophysics, Astrometry, and Astrodynamics (AAAA)
**Relative Difficulty:** 6/6
**Author:** [Cromulence](https://cromulence.com/)

This social media app is back with a vengeance!


## Building ##

This repository contains three Docker images: The `generator`, `challenge`,
and `solver`. You can build them all with:

```sh
make build
```

The resulting Docker images will be tagged as `myspace:generator`,
`myspace:challenge`, and `myspace:solver`.

You can also build just one of them with `make generator`, `make challenge`,
or `make solver` respectively.

Building the `generator` container requires having already built the
`generator-base` container (see the `generator-base` folder).


## Deploying ##

See top-level `README.md` file for more information on deploying the
`challenge` container.


## Testing ##

See top-level `README.md` file for more information on using the `solver`
container.


## Notes ##

This challenge requires teams to take a randomly generated star catalog, which 
is a list of cartesian unit vectors and associated magnitudes, and a set of 
boresight reference unit vectors in the current boresight. Their goal is to 
match the boresight vectors to a star IDs from the catalog, they need to get a
certain number correct to pass each trial.

This can be incredibly hard if needed. This is actually more of a computer 
vision challenge, requiring the teams to learn how to group stars into identifiable
clusters. The expected approach is to use the brightest stars (which are evenly
distributed, by design) and match it with every possible pairing of two other
stars within configurable range (based on FOV, to limit processing time). These
triplets will form a triangle, and can be recognized as "features", and each 
of the features will vote on which stars the algorithm thinks is represented by
the provided vectors. These votes are then used to determine the most likely 
stars. There are papers related to how to perform this that are available no the
web.

Note this could actually be even HARDER if noise is introduced, and would require
multiple parameters associated with the triangle, where as the no noise approach
can be solved with just one parameter typically. It's more realistic to have noise
but the algorithm becomes tricky.
